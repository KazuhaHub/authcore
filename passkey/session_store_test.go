package passkey

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestMemoryStore_SingleUse(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore(10, time.Minute)
	id, err := st.Put(ctx, &webauthn.SessionData{Challenge: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := st.Take(ctx, id)
	if !ok || got.Challenge != "abc" {
		t.Fatalf("first Take: got=%v ok=%v, want the stored session", got, ok)
	}
	if _, ok := st.Take(ctx, id); ok {
		t.Fatal("a consumed session must not be takeable again")
	}
	if _, ok := st.Take(ctx, "nope"); ok {
		t.Fatal("an unknown id must return ok=false")
	}
	if _, ok := st.Take(ctx, ""); ok {
		t.Fatal("an empty id must return ok=false")
	}
}

func TestMemoryStore_Expiry(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	clock := now
	st := newMemoryStore(10, time.Minute, func() time.Time { return clock })
	id, _ := st.Put(ctx, &webauthn.SessionData{Challenge: "x"})
	clock = now.Add(2 * time.Minute)
	if _, ok := st.Take(ctx, id); ok {
		t.Fatal("an expired session must not be returned")
	}
}

// TestMemoryStore_CapacityEvictsOldest proves the store never grows past
// maxItems: once full, Put evicts the oldest entry (even if unexpired) to
// make room, so a flood of abandoned Begins cannot exhaust memory.
func TestMemoryStore_CapacityEvictsOldest(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore(3, time.Hour)
	var ids []string
	for i := 0; i < 5; i++ {
		id, err := st.Put(ctx, &webauthn.SessionData{Challenge: string(rune('a' + i))})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if got := st.Len(); got != 3 {
		t.Fatalf("Len() = %d, want capacity 3", got)
	}
	// The two oldest (ids[0], ids[1]) must have been evicted.
	if _, ok := st.Take(ctx, ids[0]); ok {
		t.Fatal("the oldest entry should have been evicted to make room")
	}
	if _, ok := st.Take(ctx, ids[1]); ok {
		t.Fatal("the second-oldest entry should have been evicted to make room")
	}
	// The three most recent must still be present.
	for _, id := range ids[2:] {
		if _, ok := st.Take(ctx, id); !ok {
			t.Fatalf("recent entry %q should still be present", id)
		}
	}
}

func TestMemoryStore_DefaultsAppliedForInvalidBounds(t *testing.T) {
	st := NewMemoryStore(0, 0)
	if st.maxItems != DefaultSessionCapacity {
		t.Fatalf("maxItems = %d, want default %d", st.maxItems, DefaultSessionCapacity)
	}
	if st.ttl != DefaultSessionTTL {
		t.Fatalf("ttl = %v, want default %v", st.ttl, DefaultSessionTTL)
	}
}

// TestMemoryStore_ConcurrentPutTakeDoNotCross runs many goroutines each
// putting and immediately taking their own session, under -race, and checks
// every goroutine gets back exactly the data it put -- no cross-talk between
// concurrent ceremonies sharing one store.
func TestMemoryStore_ConcurrentPutTakeDoNotCross(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore(1000, time.Minute)
	const n = 200

	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			challenge := string(rune('A' + (i % 26)))
			data := &webauthn.SessionData{Challenge: challenge, UserID: []byte{byte(i)}}
			id, err := st.Put(ctx, data)
			if err != nil {
				errs <- err.Error()
				return
			}
			got, ok := st.Take(ctx, id)
			if !ok {
				errs <- "Take returned ok=false for an id this goroutine just Put"
				return
			}
			if got.Challenge != challenge || len(got.UserID) != 1 || got.UserID[0] != byte(i) {
				errs <- "Take returned a different goroutine's session data"
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
