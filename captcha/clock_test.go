package captcha

import (
	"testing"
	"time"
)

// This file holds MemoryStore tests that exercise expiry. They live in
// package captcha (not captcha_test) so they can reach the unexported,
// clock-injectable newMemoryStore constructor and advance a fake clock
// instead of sleeping on the wall clock — a real sleep-then-check makes the
// test's pass/fail depend on how fast the machine running it happens to be,
// which is exactly the kind of flakiness that erodes trust in CI. See
// passkey/session_store.go's newMemoryStore for the same pattern.

func TestImageGenerator_Verify_Expired(t *testing.T) {
	now := time.Now()
	clock := now
	store := newMemoryStore(0, 20*time.Millisecond, func() time.Time { return clock })
	gen := NewImageGenerator(store)

	ch, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	answer := store.Get(ch.ID, false)
	if answer == "" {
		t.Fatalf("no value stored for id %q", ch.ID)
	}

	// Advance the injected clock past the store's TTL.
	clock = now.Add(40 * time.Millisecond)

	if gen.Verify(ch.ID, answer) {
		t.Fatal("Verify succeeded for an expired challenge")
	}
}

func TestMemoryStore_ExpiredEntryIsPurged(t *testing.T) {
	now := time.Now()
	clock := now
	store := newMemoryStore(10, 15*time.Millisecond, func() time.Time { return clock })

	if err := store.Set("id1", "answer"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if store.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", store.Len())
	}

	clock = now.Add(30 * time.Millisecond)

	if got := store.Get("id1", false); got != "" {
		t.Fatalf("Get returned %q for an expired entry, want empty", got)
	}
	if got := store.Len(); got != 0 {
		t.Fatalf("Len() = %d after an expired read, want 0 (expired entries must be purged, not just hidden)", got)
	}

	// Setting a fresh entry after the ttl also purges any other expired
	// entries left over, so the store does not grow without bound even if
	// nothing ever reads the expired ids.
	if err := store.Set("id2", "answer"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := store.Set("id3", "answer"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	clock = clock.Add(30 * time.Millisecond)
	if err := store.Set("id4", "answer"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := store.Len(); got != 1 {
		t.Fatalf("Len() = %d after inserting past ttl, want 1 (id2 and id3 should have been purged)", got)
	}
}
