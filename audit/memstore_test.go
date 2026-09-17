package audit

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestMemoryStore_CapacityBound(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(3, time.Hour)

	base := time.Now().UTC()
	for i := 0; i < 5; i++ {
		e := &Event{Action: "a", ActorID: fmt.Sprint(i), Time: base.Add(time.Duration(i) * time.Second)}
		if err := s.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	got, total, err := s.Query(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || total != 3 {
		t.Fatalf("store holds %d/%d events after 5 appends with cap 3, want 3/3 (unbounded growth)", len(got), total)
	}
	// The oldest two (0, 1) must have been evicted; 2,3,4 survive.
	var ids []string
	for _, e := range got {
		ids = append(ids, e.ActorID)
	}
	want := []string{"2", "3", "4"}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("survivors = %v, want %v (oldest evicted first)", ids, want)
		}
	}
}

func TestMemoryStore_TTLExpiry(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(100, 50*time.Millisecond)

	if err := s.Append(ctx, &Event{Action: "old", Time: time.Now().UTC().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// A read (Query) must observe expiry even with no further writes.
	got, total, err := s.Query(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || total != 0 {
		t.Fatalf("an event 1h older than a 50ms ttl is still present: %+v", got)
	}

	if err := s.Append(ctx, &Event{Action: "fresh"}); err != nil {
		t.Fatal(err)
	}
	got, _, err = s.Query(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Action != "fresh" {
		t.Fatalf("fresh event missing after expiring the old one: %+v", got)
	}
}

func TestMemoryStore_DefaultsAppliedForNonPositiveArgs(t *testing.T) {
	s := NewMemoryStore(0, 0)
	if s.maxItems != DefaultMemoryStoreCapacity {
		t.Errorf("maxItems = %d, want default %d", s.maxItems, DefaultMemoryStoreCapacity)
	}
	if s.ttl != DefaultMemoryStoreTTL {
		t.Errorf("ttl = %v, want default %v", s.ttl, DefaultMemoryStoreTTL)
	}

	s = NewMemoryStore(-5, -time.Second)
	if s.maxItems != DefaultMemoryStoreCapacity || s.ttl != DefaultMemoryStoreTTL {
		t.Errorf("negative args not replaced with defaults: maxItems=%d ttl=%v", s.maxItems, s.ttl)
	}
}

func TestMemoryStore_Head(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(0, 0)

	head, err := s.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head != nil {
		t.Fatalf("Head of empty store = %+v, want nil", head)
	}

	if err := s.Append(ctx, &Event{Action: "a", ActorID: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ctx, &Event{Action: "a", ActorID: "2"}); err != nil {
		t.Fatal(err)
	}
	head, err = s.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head == nil || head.ActorID != "2" {
		t.Fatalf("Head = %+v, want the most recently appended event", head)
	}
}

// Concurrent Append/Query must not race or corrupt Seq assignment
// (run with -race).
func TestMemoryStore_ConcurrentAppend(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(10_000, time.Hour)

	const goroutines = 20
	const perGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				e := &Event{Action: "concurrent", ActorID: fmt.Sprintf("%d-%d", g, i)}
				if err := s.Append(ctx, e); err != nil {
					t.Errorf("append: %v", err)
				}
			}
		}(g)
	}
	wg.Wait()

	_, total, err := s.Query(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if total != goroutines*perGoroutine {
		t.Fatalf("total = %d, want %d", total, goroutines*perGoroutine)
	}

	// Seq values must all be distinct (no lost updates under the lock).
	all, _, err := s.Query(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[int64]bool, len(all))
	for _, e := range all {
		if seen[e.Seq] {
			t.Fatalf("duplicate Seq %d under concurrent append", e.Seq)
		}
		seen[e.Seq] = true
	}
}
