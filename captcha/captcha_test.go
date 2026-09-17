package captcha_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/authcore/captcha"
)

// answerFor peeks at the value a Store holds for id without consuming it, so
// a test can learn the digit driver's generated answer without the package
// exposing it on Challenge (a real caller never gets to see it either).
func answerFor(t *testing.T, store captcha.Store, id string) string {
	t.Helper()
	v := store.Get(id, false)
	if v == "" {
		t.Fatalf("no value stored for id %q", id)
	}
	return v
}

func TestImageGenerator_GenerateAndVerify_Success(t *testing.T) {
	store := captcha.NewMemoryStore(0, 0)
	gen := captcha.NewImageGenerator(store)

	ch, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if ch.ID == "" {
		t.Fatal("Generate returned empty ID")
	}
	if ch.Image == "" {
		t.Fatal("Generate returned empty Image")
	}

	answer := answerFor(t, store, ch.ID)

	if !gen.Verify(ch.ID, answer) {
		t.Fatal("Verify with the correct answer returned false")
	}
}

func TestImageGenerator_Verify_WrongAnswer(t *testing.T) {
	store := captcha.NewMemoryStore(0, 0)
	gen := captcha.NewImageGenerator(store)

	ch, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if gen.Verify(ch.ID, "not-the-right-answer") {
		t.Fatal("Verify with a wrong answer returned true")
	}
}

func TestImageGenerator_Verify_EmptyIDOrAnswer(t *testing.T) {
	store := captcha.NewMemoryStore(0, 0)
	gen := captcha.NewImageGenerator(store)

	ch, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	answer := answerFor(t, store, ch.ID)

	if gen.Verify("", answer) {
		t.Fatal("Verify with an empty id returned true")
	}
	if gen.Verify(ch.ID, "") {
		t.Fatal("Verify with an empty answer returned true")
	}
	// Neither empty-input call should have touched the store: the real
	// answer must still verify afterward.
	if !gen.Verify(ch.ID, answer) {
		t.Fatal("challenge was consumed by an empty-input Verify call")
	}
}

func TestImageGenerator_Verify_SingleUse(t *testing.T) {
	store := captcha.NewMemoryStore(0, 0)
	gen := captcha.NewImageGenerator(store)

	ch, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	answer := answerFor(t, store, ch.ID)

	if !gen.Verify(ch.ID, answer) {
		t.Fatal("first Verify with the correct answer returned false")
	}
	if gen.Verify(ch.ID, answer) {
		t.Fatal("second Verify with the same id and the correct answer returned true; challenges must be single-use")
	}
}

func TestImageGenerator_Verify_WrongAnswerAlsoConsumesChallenge(t *testing.T) {
	// A wrong guess must burn the challenge too, otherwise an attacker can
	// retry the same id forever.
	store := captcha.NewMemoryStore(0, 0)
	gen := captcha.NewImageGenerator(store)

	ch, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	answer := answerFor(t, store, ch.ID)

	if gen.Verify(ch.ID, "definitely-wrong") {
		t.Fatal("Verify with a wrong answer returned true")
	}
	if gen.Verify(ch.ID, answer) {
		t.Fatal("Verify with the correct answer succeeded after a prior wrong guess; the challenge should already be consumed")
	}
}

// TestImageGenerator_Verify_Expired lives in clock_test.go (package captcha,
// not captcha_test): it needs the unexported, clock-injectable
// newMemoryStore constructor so it can advance a fake clock past the TTL
// instead of sleeping on the wall clock.

func TestImageGenerator_ConcurrentGenerate_NoCollisions(t *testing.T) {
	store := captcha.NewMemoryStore(1000, time.Minute)
	gen := captcha.NewImageGenerator(store)

	const n = 200
	ids := make([]string, n)
	errs := make([]error, n)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			ch, err := gen.Generate()
			ids[i] = ch.ID
			errs[i] = err
		}(i)
	}
	wg.Wait()

	seen := make(map[string]bool, n)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Generate #%d: %v", i, err)
		}
		if ids[i] == "" {
			t.Fatalf("Generate #%d returned an empty id", i)
		}
		if seen[ids[i]] {
			t.Fatalf("duplicate id %q generated concurrently", ids[i])
		}
		seen[ids[i]] = true
	}

	// Every id issued while under the store's capacity must still be
	// independently verifiable.
	var wg2 sync.WaitGroup
	results := make([]bool, n)
	wg2.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg2.Done()
			answer := answerFor(t, store, ids[i])
			results[i] = gen.Verify(ids[i], answer)
		}(i)
	}
	wg2.Wait()
	for i, ok := range results {
		if !ok {
			t.Fatalf("concurrent Verify #%d (id %q) failed", i, ids[i])
		}
	}
}

func TestMemoryStore_SetGetVerify(t *testing.T) {
	store := captcha.NewMemoryStore(10, time.Minute)

	if err := store.Set("id1", "4242"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := store.Get("id1", false); got != "4242" {
		t.Fatalf("Get = %q, want %q", got, "4242")
	}
	if !store.Verify("id1", "4242", false) {
		t.Fatal("Verify with the correct answer returned false")
	}
	// clear=false: a repeat check must still succeed.
	if !store.Verify("id1", "4242", false) {
		t.Fatal("Verify without clear did not allow a repeat check")
	}
	if store.Verify("id1", "4242", true) != true {
		t.Fatal("Verify with clear=true and the correct answer returned false")
	}
	// Now consumed.
	if store.Verify("id1", "4242", false) {
		t.Fatal("Verify succeeded after the entry was cleared")
	}
}

func TestMemoryStore_CapacityCapEnforced(t *testing.T) {
	const capacity = 3
	store := captcha.NewMemoryStore(capacity, time.Minute)

	ids := make([]string, 0, capacity+2)
	for i := 0; i < capacity+2; i++ {
		id := fmt.Sprintf("id-%d", i)
		if err := store.Set(id, "answer"); err != nil {
			t.Fatalf("Set(%q): %v", id, err)
		}
		ids = append(ids, id)
	}

	if got := store.Len(); got != capacity {
		t.Fatalf("Len() = %d, want %d (capacity must not be exceeded)", got, capacity)
	}

	// The oldest entries were evicted to make room.
	for _, id := range ids[:2] {
		if store.Get(id, false) != "" {
			t.Fatalf("evicted id %q is still readable", id)
		}
	}
	// The most recent entries survived.
	for _, id := range ids[2:] {
		if store.Get(id, false) == "" {
			t.Fatalf("recent id %q was unexpectedly evicted", id)
		}
	}
}

// TestMemoryStore_ExpiredEntryIsPurged lives in clock_test.go (package
// captcha, not captcha_test): see the comment above for why.

func TestMemoryStore_DefaultsAppliedForZeroValues(t *testing.T) {
	store := captcha.NewMemoryStore(0, 0)
	if store == nil {
		t.Fatal("NewMemoryStore(0, 0) returned nil")
	}
	if err := store.Set("id1", "answer"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if store.Get("id1", false) != "answer" {
		t.Fatal("store built with zero-value args did not behave like a usable store")
	}
}
