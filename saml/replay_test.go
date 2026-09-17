package saml

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemoryReplayCache_SeenOrAdd(t *testing.T) {
	c := NewMemoryReplayCache(0)
	ctx := context.Background()
	now := time.Now()
	exp := now.Add(time.Minute)

	seen, err := c.SeenOrAdd(ctx, "id-1", exp, now)
	if err != nil {
		t.Fatalf("first SeenOrAdd: %v", err)
	}
	if seen {
		t.Fatal("first SeenOrAdd reported seen=true, want false")
	}

	seen, err = c.SeenOrAdd(ctx, "id-1", exp, now)
	if err != nil {
		t.Fatalf("second SeenOrAdd: %v", err)
	}
	if !seen {
		t.Fatal("second SeenOrAdd reported seen=false, want true")
	}

	// A different ID is unaffected.
	seen, err = c.SeenOrAdd(ctx, "id-2", exp, now)
	if err != nil || seen {
		t.Fatalf("SeenOrAdd for a distinct id: seen=%v err=%v, want false/nil", seen, err)
	}
}

func TestMemoryReplayCache_ExpiredEntryIsNotSeen(t *testing.T) {
	c := NewMemoryReplayCache(0)
	ctx := context.Background()
	now := time.Now()

	if seen, err := c.SeenOrAdd(ctx, "id-1", now.Add(time.Second), now); err != nil || seen {
		t.Fatalf("initial add: seen=%v err=%v", seen, err)
	}

	// Ask again after the entry's own expiresAt has passed: the cache
	// itself does not remember this as "seen" any more (see the comment
	// on MemoryReplayCache.SeenOrAdd — the assertion's own time-window
	// check, not the cache, is what must have already rejected a replay
	// by this point in real use).
	later := now.Add(2 * time.Second)
	seen, err := c.SeenOrAdd(ctx, "id-1", later.Add(time.Minute), later)
	if err != nil {
		t.Fatalf("SeenOrAdd after expiry: %v", err)
	}
	if seen {
		t.Fatal("SeenOrAdd after expiry reported seen=true, want false (the cache should have room again)")
	}
}

func TestMemoryReplayCache_EmptyIDNeverSeen(t *testing.T) {
	c := NewMemoryReplayCache(0)
	ctx := context.Background()
	now := time.Now()
	for i := 0; i < 3; i++ {
		seen, err := c.SeenOrAdd(ctx, "", now.Add(time.Minute), now)
		if err != nil || seen {
			t.Fatalf("iteration %d: seen=%v err=%v, want false/nil", i, seen, err)
		}
	}
	if c.Len() != 0 {
		t.Errorf("Len() = %d, want 0 (empty id must not be stored)", c.Len())
	}
}

// TestMemoryReplayCache_Concurrent is the core replay-cache guarantee:
// many goroutines racing SeenOrAdd on the SAME id must produce exactly one
// "not seen" (the winner) and every other call must report "seen".
func TestMemoryReplayCache_Concurrent(t *testing.T) {
	c := NewMemoryReplayCache(0)
	ctx := context.Background()
	now := time.Now()
	exp := now.Add(time.Minute)

	const n = 200
	var wg sync.WaitGroup
	results := make([]bool, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			seen, err := c.SeenOrAdd(ctx, "race-id", exp, now)
			if err != nil {
				t.Errorf("SeenOrAdd: %v", err)
			}
			results[i] = seen
		}(i)
	}
	wg.Wait()

	var notSeenCount int
	for _, seen := range results {
		if !seen {
			notSeenCount++
		}
	}
	if notSeenCount != 1 {
		t.Errorf("notSeenCount = %d, want exactly 1", notSeenCount)
	}
}

func TestMemoryReplayCache_CapacityBound(t *testing.T) {
	const capacity = 100
	c := NewMemoryReplayCache(capacity)
	ctx := context.Background()
	now := time.Now()
	// Every entry valid for a long time, so the sweep-expired-first pass
	// in evictToFit cannot free anything and the low-water eviction must
	// kick in instead.
	exp := now.Add(24 * time.Hour)

	for i := 0; i < capacity*5; i++ {
		id := randomID(i)
		if _, err := c.SeenOrAdd(ctx, id, exp, now); err != nil {
			t.Fatalf("SeenOrAdd(%d): %v", i, err)
		}
		if c.Len() > capacity {
			t.Fatalf("Len() = %d after %d inserts, exceeds capacity %d", c.Len(), i+1, capacity)
		}
	}
}

func TestMemoryReplayCache_SweepsExpiredBeforeEvicting(t *testing.T) {
	const capacity = 50
	c := NewMemoryReplayCache(capacity)
	ctx := context.Background()
	now := time.Now()

	// Fill to capacity with entries that are already expired as of `now`.
	for i := 0; i < capacity; i++ {
		if _, err := c.SeenOrAdd(ctx, randomID(i), now.Add(-time.Second), now.Add(-time.Minute)); err != nil {
			t.Fatalf("seed insert %d: %v", i, err)
		}
	}
	if c.Len() != capacity {
		t.Fatalf("Len() = %d, want %d after seeding", c.Len(), capacity)
	}

	// One more insert, still valid, should trigger the expired sweep and
	// leave the cache well under capacity rather than evicting anything
	// unnecessarily via the low-water path.
	if _, err := c.SeenOrAdd(ctx, "fresh", now.Add(time.Hour), now); err != nil {
		t.Fatalf("insert after seeding: %v", err)
	}
	if c.Len() != 1 {
		t.Fatalf("Len() = %d after sweep, want 1 (only the fresh entry should remain)", c.Len())
	}
}

func randomID(i int) string {
	// Deterministic, distinct IDs; no need for real randomness in a test.
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 0, 16)
	n := i + 1
	for n > 0 {
		b = append(b, alphabet[n%len(alphabet)])
		n /= len(alphabet)
	}
	return "id-" + string(b)
}
