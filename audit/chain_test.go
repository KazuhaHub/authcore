package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fixedClock returns a clock function that always reports t, for tests
// that must not depend on the wall clock (Chain and MemoryStore both take
// an injectable clock via their unexported newChain/newMemoryStore
// constructors for exactly this reason).
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// sliceReader is a minimal Reader over a fixed, directly-mutable slice, used
// to test Verify against hand-built (and hand-tampered) chains without
// going through a real Store's Append path.
type sliceReader []*Event

func (s sliceReader) Query(ctx context.Context, f Filter) ([]*Event, int, error) {
	var out []*Event
	for _, e := range s {
		if matchFilter(e, f) {
			out = append(out, e)
		}
	}
	total := len(out)
	if f.Offset > 0 {
		if f.Offset >= len(out) {
			out = nil
		} else {
			out = out[f.Offset:]
		}
	}
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, total, nil
}

// buildChain hand-constructs n validly hash-chained events starting from
// anchor, so tests can exercise Verify directly without needing a live
// Store/Chain pair.
func buildChain(n int, anchor string, base time.Time) []*Event {
	prev := anchor
	out := make([]*Event, 0, n)
	for i := 0; i < n; i++ {
		e := &Event{
			Seq:       int64(i + 1),
			Time:      base.Add(time.Duration(i) * time.Second),
			Action:    "test.action",
			ActorType: "user",
			ActorID:   fmt.Sprintf("actor-%d", i),
		}
		e.PrevHash = prev
		e.Hash = hashEvent(e, prev)
		out = append(out, e)
		prev = e.Hash
	}
	return out
}

func TestVerify_EmptyIsOK(t *testing.T) {
	res, err := Verify(context.Background(), sliceReader(nil), Filter{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Count != 0 {
		t.Fatalf("Verify(empty) = %+v, want OK with 0", res)
	}
}

func TestVerify_ValidChainPasses(t *testing.T) {
	events := buildChain(5, "", time.Now())
	res, err := Verify(context.Background(), sliceReader(events), Filter{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Count != 5 {
		t.Fatalf("Verify(valid chain) = %+v, want OK with 5", res)
	}
}

// The whole point of the chain: editing a field of a middle entry must be
// detected.
func TestVerify_DetectsTamperedMiddleEntry(t *testing.T) {
	events := buildChain(5, "", time.Now())
	events[2].ActorID = "mallory" // tamper, content changes, hash no longer matches
	res, err := Verify(context.Background(), sliceReader(events), Filter{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("SECURITY: a tampered middle entry went undetected")
	}
	if res.BadSeq != events[2].Seq {
		t.Fatalf("BadSeq = %d, want %d (the tampered entry)", res.BadSeq, events[2].Seq)
	}
	if !strings.Contains(res.Reason, "hash does not match") {
		t.Fatalf("Reason = %q, want it to name a hash mismatch", res.Reason)
	}
}

// Removing an entry must break the link of everything that came after it.
func TestVerify_DetectsDeletedEntry(t *testing.T) {
	events := buildChain(5, "", time.Now())
	events = append(events[:2], events[3:]...) // delete index 2

	res, err := Verify(context.Background(), sliceReader(events), Filter{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("SECURITY: a deleted entry went undetected")
	}
	// The survivor that used to follow the deleted one (originally index 3)
	// now fails first: its PrevHash points at the removed entry's Hash.
	if !strings.Contains(res.Reason, "prev_hash") {
		t.Fatalf("Reason = %q, want it to name a broken link", res.Reason)
	}
}

func TestVerify_WrongAnchorFails(t *testing.T) {
	events := buildChain(3, "", time.Now())
	res, err := Verify(context.Background(), sliceReader(events), Filter{}, "0000not-the-real-anchor")
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("Verify passed with an anchor that doesn't match the first event's PrevHash")
	}
	if res.BadSeq != events[0].Seq {
		t.Fatalf("BadSeq = %d, want %d (the first event)", res.BadSeq, events[0].Seq)
	}
}

// The documented gotcha: legacy events written before chaining existed have
// PrevHash=="" and Hash=="" (never computed). A whole-range verify against
// anchor="" must see this as a break (it genuinely cannot tell "pre-chain
// history" from "hash wiped by an attacker" without help) — but scoping the
// Filter to only the chained tail, with anchor="", must pass cleanly. This
// is the exact anchor semantics Verify's doc comment promises.
func TestVerify_LegacyPrefixNeedsAnchorScoping(t *testing.T) {
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	// Two "legacy" events: real content, but never hashed (PrevHash/Hash
	// both zero-value), exactly like rows written before a Chain existed.
	legacy := []*Event{
		{Seq: 1, Time: base, Action: "legacy.action", ActorID: "old-1"},
		{Seq: 2, Time: base.Add(time.Second), Action: "legacy.action", ActorID: "old-2"},
	}
	// Chaining starts here: first chained event's PrevHash is legitimately
	// "" because it has no chained predecessor.
	chained := buildChain(3, "", base.Add(time.Hour))
	for i, e := range chained {
		e.Seq = int64(10 + i) // distinct Seq range from the legacy prefix
	}

	all := append(append([]*Event{}, legacy...), chained...)
	reader := sliceReader(all)
	ctx := context.Background()

	// Whole-table verify from genesis reports a break — expected, and
	// exactly the trap the task calls out: it fires on the FIRST legacy
	// event already, since its Hash=="" cannot match a freshly computed
	// hash of real content.
	full, err := Verify(ctx, reader, Filter{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if full.OK {
		t.Fatal("expected the whole-table verify to report a break on unhashed legacy data")
	}

	// Scoped to the chained range (AfterSeq skips the legacy prefix) with
	// anchor="" (the first chained event's real PrevHash), verification
	// must pass — this is the fix, not a workaround.
	scoped, err := Verify(ctx, reader, Filter{AfterSeq: 9}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !scoped.OK {
		t.Fatalf("scoped verify (anchor after the legacy prefix) should pass, got %+v", scoped)
	}
	if scoped.Count != len(chained) {
		t.Fatalf("scoped verify examined %d events, want %d", scoped.Count, len(chained))
	}
}

// End-to-end: Chain wrapping a real Store, appended for real, must Verify
// cleanly with no hand-built events involved.
func TestChain_EndToEndAppendAndVerify(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(0, time.Hour)
	c := NewChain(store)

	for i := 0; i < 6; i++ {
		e := &Event{Action: "chain.append", ActorType: "user", ActorID: fmt.Sprint(i)}
		if err := c.Append(ctx, e); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if e.Hash == "" || len(e.Hash) != 64 {
			t.Fatalf("append %d: Hash = %q, want a 64-char sha256 hex", i, e.Hash)
		}
	}

	res, err := Verify(ctx, store, Filter{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Count != 6 {
		t.Fatalf("Verify = %+v, want OK with 6", res)
	}
}

// A Chain resuming over a Store that already has chained history (e.g. the
// process restarted) must pick up the real head via HeadReader, not
// silently restart the chain from genesis.
func TestChain_ResumesFromExistingHead(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(0, time.Hour)

	c1 := NewChain(store)
	first := &Event{Action: "a"}
	if err := c1.Append(ctx, first); err != nil {
		t.Fatal(err)
	}

	// A fresh Chain over the same store (simulating a restart).
	c2 := NewChain(store)
	second := &Event{Action: "b"}
	if err := c2.Append(ctx, second); err != nil {
		t.Fatal(err)
	}
	if second.PrevHash != first.Hash {
		t.Fatalf("second.PrevHash = %q, want it to link to the first event's hash %q", second.PrevHash, first.Hash)
	}

	res, err := Verify(ctx, store, Filter{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Count != 2 {
		t.Fatalf("Verify across a resumed chain = %+v, want OK with 2", res)
	}
}

// Wrapping a Store that has no HeadReader must still work, via the
// full-scan fallback.
func TestChain_FallsBackWithoutHeadReader(t *testing.T) {
	ctx := context.Background()
	inner := NewMemoryStore(0, time.Hour)
	wrapped := plainStore{inner} // does not implement HeadReader

	c := NewChain(wrapped)
	a := &Event{Action: "a"}
	if err := c.Append(ctx, a); err != nil {
		t.Fatal(err)
	}
	b := &Event{Action: "b"}
	if err := c.Append(ctx, b); err != nil {
		t.Fatal(err)
	}
	if b.PrevHash != a.Hash {
		t.Fatalf("b.PrevHash = %q, want %q", b.PrevHash, a.Hash)
	}
	res, err := Verify(ctx, wrapped, Filter{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Count != 2 {
		t.Fatalf("Verify = %+v, want OK with 2", res)
	}
}

// plainStore exposes only the Store interface of a MemoryStore, hiding its
// Head method so Chain must use the fallback path.
type plainStore struct {
	s Store
}

func (p plainStore) Append(ctx context.Context, e *Event) error { return p.s.Append(ctx, e) }
func (p plainStore) Query(ctx context.Context, f Filter) ([]*Event, int, error) {
	return p.s.Query(ctx, f)
}

// An unchained Store (no Chain involved at all) must work exactly like any
// other Store — Verify is simply never called, which is a legitimate,
// permanent way to use this package.
func TestChain_UnchainedStoreWorksNormally(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(0, time.Hour)
	e := &Event{Action: "no.chain", ActorType: "device", ActorID: "d1"}
	if err := store.Append(ctx, e); err != nil {
		t.Fatal(err)
	}
	if e.Hash != "" || e.PrevHash != "" {
		t.Fatalf("an Event appended without a Chain must not have chain fields set: %+v", e)
	}
	got, total, err := store.Query(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || got[0].Action != "no.chain" {
		t.Fatalf("unchained store did not behave like a normal Store: %+v", got)
	}
}

// Concurrent appends through one Chain must not fork or corrupt the chain:
// every event ends up linearly linked and Verify passes. Run with -race.
func TestChain_ConcurrentAppendStaysLinear(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(10_000, time.Hour)
	c := NewChain(store)

	const goroutines = 10
	const perGoroutine = 30

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				e := &Event{Action: "concurrent.chain", ActorID: fmt.Sprintf("%d-%d", g, i)}
				if err := c.Append(ctx, e); err != nil {
					t.Errorf("append: %v", err)
				}
			}
		}(g)
	}
	wg.Wait()

	res, err := Verify(ctx, store, Filter{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("concurrent chain appends produced a broken chain: %+v", res)
	}
	if res.Count != goroutines*perGoroutine {
		t.Fatalf("Verify examined %d events, want %d", res.Count, goroutines*perGoroutine)
	}
}

// Retention (MemoryStore's TTL/capacity eviction) removing the oldest
// chained events is the same anchor situation as a deliberate prune: the
// surviving prefix's PrevHash points at a hash that is no longer stored.
// Verifying from genesis must report that as a break; verifying from the
// hash of the last event that existed before eviction (an anchor the
// caller is responsible for having recorded — this package does not do it
// automatically) must pass.
func TestChain_EvictionActsAsAPruneAndNeedsAnAnchor(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(3, time.Hour) // tiny cap: forces eviction
	c := NewChain(store)

	var appended []*Event
	for i := 0; i < 6; i++ {
		e := &Event{Action: "evict.me", ActorID: fmt.Sprint(i)}
		if err := c.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
		appended = append(appended, e)
	}

	// Only the last 3 survive; the anchor for what remains is the hash of
	// the last evicted event (index 2, the 3rd appended).
	anchor := appended[2].Hash

	broken, err := Verify(ctx, store, Filter{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if broken.OK {
		t.Fatal("expected genesis verify to report a break after eviction removed the chain's start")
	}

	fixed, err := Verify(ctx, store, Filter{}, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if !fixed.OK || fixed.Count != 3 {
		t.Fatalf("anchored verify after eviction = %+v, want OK with 3", fixed)
	}
}

func TestChain_RejectsEmptyAction(t *testing.T) {
	ctx := context.Background()
	c := NewChain(NewMemoryStore(0, 0))
	if err := c.Append(ctx, &Event{ActorID: "x"}); err != ErrActionRequired {
		t.Fatalf("Chain.Append with no Action = %v, want ErrActionRequired", err)
	}
}

// Identical content at different chain positions must still get distinct
// hashes, since each links to a different predecessor — otherwise two
// identical entries could be swapped without Verify noticing.
func TestChain_IdenticalContentDistinctHashes(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(0, time.Hour)
	c := NewChain(store)

	mk := func() *Event {
		return &Event{Time: time.Unix(1765238400, 0).UTC(), Action: "same.action", ActorType: "user", ActorID: "same", TargetID: "same"}
	}
	a, b := mk(), mk()
	if err := c.Append(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := c.Append(ctx, b); err != nil {
		t.Fatal(err)
	}
	if a.Hash == b.Hash {
		t.Fatal("identical content at two different chain positions produced the same hash")
	}
	if b.PrevHash != a.Hash {
		t.Fatalf("second event must link to the first: PrevHash=%q, first hash=%q", b.PrevHash, a.Hash)
	}
}

// dropsChainFieldsStore wraps a *MemoryStore but strips PrevHash/Hash from
// every Event before forwarding it to Append — the exact shape of the
// Report Portal audit_log adapter that motivated this check: its table
// simply has no columns for either field, so a Chain's computed hashes
// never reach storage even though Append returns nil and nothing else
// about the write looks wrong. It does not implement HeadReader, so a
// Chain wrapping it must fall back to Query for its read-back.
type dropsChainFieldsStore struct {
	inner *MemoryStore
}

func (d *dropsChainFieldsStore) Append(ctx context.Context, e *Event) error {
	cp := *e
	cp.PrevHash = ""
	cp.Hash = ""
	if err := d.inner.Append(ctx, &cp); err != nil {
		return err
	}
	// A real adapter still assigns Seq/Time as any compliant Store must;
	// only PrevHash/Hash are the ones being dropped.
	e.Seq = cp.Seq
	e.Time = cp.Time
	return nil
}

func (d *dropsChainFieldsStore) Query(ctx context.Context, f Filter) ([]*Event, int, error) {
	return d.inner.Query(ctx, f)
}

// dropsChainFieldsHeadStore is dropsChainFieldsStore plus a HeadReader
// implementation, so a test can exercise the integrity check's HeadReader
// branch (not just the Query fallback) against a Store that drops the
// chain fields.
type dropsChainFieldsHeadStore struct {
	dropsChainFieldsStore
}

func (d *dropsChainFieldsHeadStore) Head(ctx context.Context) (*Event, error) {
	return d.inner.Head(ctx)
}

// The central regression test: a Store shaped like Report Portal's
// audit_log adapter (no columns for PrevHash/Hash, so Append silently
// drops them) must be caught on the first Append, with a clear sentinel
// error — not discovered later, and not later still, only when someone
// happens to call Verify.
func TestChain_DetectsStoreThatDropsChainFields(t *testing.T) {
	ctx := context.Background()
	fixed := fixedClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	store := &dropsChainFieldsStore{inner: newMemoryStore(0, time.Hour, fixed)}
	c := newChain(store, fixed)

	err := c.Append(ctx, &Event{Action: "session.create"})
	if !errors.Is(err, ErrStoreDropsChainFields) {
		t.Fatalf("Append against a field-dropping store = %v, want ErrStoreDropsChainFields", err)
	}
	// The error must tell an operator which two fields the adapter needs
	// to add storage for.
	if !strings.Contains(err.Error(), "PrevHash") || !strings.Contains(err.Error(), "Hash") {
		t.Fatalf("error message = %q, want it to name PrevHash and Hash", err.Error())
	}
}

// Same defect, but on a Store that also implements HeadReader (like
// MemoryStore does): the integrity check must catch it via the HeadReader
// branch of its read-back, not only the Query fallback.
func TestChain_DetectsStoreThatDropsChainFieldsViaHeadReader(t *testing.T) {
	ctx := context.Background()
	fixed := fixedClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	store := &dropsChainFieldsHeadStore{dropsChainFieldsStore{inner: newMemoryStore(0, time.Hour, fixed)}}
	c := newChain(store, fixed)

	err := c.Append(ctx, &Event{Action: "session.create"})
	if !errors.Is(err, ErrStoreDropsChainFields) {
		t.Fatalf("Append against a field-dropping HeadReader store = %v, want ErrStoreDropsChainFields", err)
	}
}

// A compliant Store (MemoryStore, and the same Store via the Query
// fallback with HeadReader hidden) must never trip the integrity check.
func TestChain_IntegrityCheckPassesForCompliantStore(t *testing.T) {
	ctx := context.Background()
	fixed := fixedClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	for name, store := range map[string]Store{
		"MemoryStore (HeadReader path)": newMemoryStore(0, time.Hour, fixed),
		"plainStore (Query fallback)":   plainStore{newMemoryStore(0, time.Hour, fixed)},
	} {
		t.Run(name, func(t *testing.T) {
			c := newChain(store, fixed)
			for i := 0; i < 3; i++ {
				e := &Event{Action: "session.create", ActorID: fmt.Sprint(i)}
				if err := c.Append(ctx, e); err != nil {
					t.Fatalf("append %d against a compliant store: unexpected error %v", i, err)
				}
			}
		})
	}
}

// countingHeadStore wraps a *MemoryStore and counts calls to Head/Query,
// so a test can assert the integrity check's read-back happens exactly
// once per Chain, no matter how many Appends follow.
type countingHeadStore struct {
	*MemoryStore
	heads   int32
	queries int32
}

func (c *countingHeadStore) Head(ctx context.Context) (*Event, error) {
	atomic.AddInt32(&c.heads, 1)
	return c.MemoryStore.Head(ctx)
}

func (c *countingHeadStore) Query(ctx context.Context, f Filter) ([]*Event, int, error) {
	atomic.AddInt32(&c.queries, 1)
	return c.MemoryStore.Query(ctx, f)
}

// The integrity check must run at most once per Chain: extra Appends
// beyond the first must not perform an extra read.
func TestChain_IntegrityCheckRunsOnlyOnce(t *testing.T) {
	ctx := context.Background()
	fixed := fixedClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	cs := &countingHeadStore{MemoryStore: newMemoryStore(0, time.Hour, fixed)}
	c := newChain(cs, fixed)

	const n = 5
	for i := 0; i < n; i++ {
		if err := c.Append(ctx, &Event{Action: "session.create", ActorID: fmt.Sprint(i)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	// Exactly 2 Head calls total across n Appends: loadHead's own
	// current-tail lookup (once, on the first Append only — it latches via
	// c.ready) plus the integrity check's read-back (once, on the first
	// Append only — it latches via c.checked). Every Append after the
	// first skips both, however many more there are.
	if got := atomic.LoadInt32(&cs.heads); got != 2 {
		t.Fatalf("Head called %d times across %d Appends, want exactly 2 (loadHead once + integrity check once)", got, n)
	}
	if got := atomic.LoadInt32(&cs.queries); got != 0 {
		t.Fatalf("Query called %d times, want 0: the HeadReader path should be used throughout, never the Query fallback", got)
	}
}

// WithoutStoreIntegrityCheck must actually suppress the check: Append
// against a field-dropping store succeeds when the option is set (the
// tradeoff the option exists to offer), even though the dropped fields
// are real and would otherwise make Verify fail later.
func TestChain_WithoutStoreIntegrityCheckDisablesDetection(t *testing.T) {
	ctx := context.Background()
	fixed := fixedClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	store := &dropsChainFieldsStore{inner: newMemoryStore(0, time.Hour, fixed)}
	c := newChain(store, fixed, WithoutStoreIntegrityCheck())

	if err := c.Append(ctx, &Event{Action: "session.create"}); err != nil {
		t.Fatalf("Append with the integrity check disabled = %v, want nil", err)
	}

	// Confirm this test is actually exercising the option and not just
	// passing by accident: the fields really were dropped, so Verify must
	// still catch the resulting hash mismatch.
	res, err := Verify(ctx, store, Filter{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("expected Verify to detect the store's dropped hash even with the Chain integrity check disabled")
	}
}
