package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Chain wraps a Store and links every appended Event to its predecessor by
// a SHA-256 hash, so Verify can later detect an edited, inserted, or
// removed Event. See the package doc for exactly what this does and does
// not protect against, and Verify's doc comment for the anchor concept
// pruning and pre-chain history both require.
//
// Using a Chain is entirely optional: a Store works standalone, and an
// unchained Event (PrevHash and Hash both empty) is a normal, permanent,
// fully supported thing for a Store to hold — not a degraded state.
//
// Chain itself implements Store (Append/Query), so callers can pass either
// a plain Store or a *Chain wherever a Store is expected. A *Chain's own
// Query is a passthrough to the wrapped Store — filtering and pagination
// are unaffected by chaining.
type Chain struct {
	store Store
	now   func() time.Time

	mu    sync.Mutex
	head  string
	ready bool
}

// NewChain wraps store so that Appends made through the returned Chain are
// hash-linked. Wrap the innermost Store once; do not layer multiple Chains
// over the same Store, or Appends made directly against the Store (bypassing
// the Chain) — both leave the chain unable to see every link.
func NewChain(store Store) *Chain {
	return newChain(store, time.Now)
}

// newChain is NewChain with an injectable clock, for tests.
func newChain(store Store, now func() time.Time) *Chain {
	if now == nil {
		now = time.Now
	}
	return &Chain{store: store, now: now}
}

// loadHead establishes c.head from the wrapped store's current tail. Caller
// must hold c.mu. Idempotent: subsequent calls are a no-op once c.ready.
func (c *Chain) loadHead(ctx context.Context) error {
	if c.ready {
		return nil
	}
	if hr, ok := c.store.(HeadReader); ok {
		e, err := hr.Head(ctx)
		if err != nil {
			return err
		}
		if e != nil {
			c.head = e.Hash
		}
		c.ready = true
		return nil
	}
	// Fallback for a Store that doesn't implement HeadReader: a full,
	// ascending scan to find the last event. Correct but O(n); SQL
	// adapters are encouraged to implement HeadReader (e.g. `ORDER BY id
	// DESC LIMIT 1`) to avoid this.
	events, _, err := c.store.Query(ctx, Filter{})
	if err != nil {
		return err
	}
	if len(events) > 0 {
		c.head = events[len(events)-1].Hash
	}
	c.ready = true
	return nil
}

// Append computes e.PrevHash and e.Hash from the chain's current head and
// e's content, then appends e to the wrapped Store. Concurrent Appends
// through the same Chain are serialized so the chain never forks: each
// Append fully completes (including the underlying Store.Append) before the
// next one reads the head, so two concurrent callers cannot both link onto
// the same predecessor.
func (c *Chain) Append(ctx context.Context, e *Event) error {
	if e.Action == "" {
		return ErrActionRequired
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.loadHead(ctx); err != nil {
		return err
	}
	if e.Time.IsZero() {
		e.Time = c.now().UTC()
	}
	e.PrevHash = c.head
	e.Hash = hashEvent(e, c.head)

	if err := c.store.Append(ctx, e); err != nil {
		return err
	}
	c.head = e.Hash
	return nil
}

// Query implements Reader by delegating to the wrapped Store.
func (c *Chain) Query(ctx context.Context, f Filter) ([]*Event, int, error) {
	return c.store.Query(ctx, f)
}

// canonicalBytes is the exact byte string hashEvent hashes. Field order is
// fixed and every value is length-prefixed, so no combination of field
// contents can be rearranged to collide with a different Event's encoding
// (e.g. Action="ab",TargetID="c" cannot be confused with
// Action="a",TargetID="bc").
//
// Seq is deliberately NOT part of the hash: it is a Store-assigned
// position, not content, and different Store implementations (or a
// migration between them) may assign different Seqs to what is otherwise
// the same event. Ordering during Verify comes from Query's contract
// (ascending Seq), not from the hash.
func canonicalBytes(e *Event, prevHash string) []byte {
	var b strings.Builder
	put := func(s string) {
		b.WriteString(strconv.Itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
		b.WriteByte('|')
	}
	put(prevHash)
	put(e.Time.UTC().Format(time.RFC3339Nano))
	put(e.Action)
	put(e.ActorType)
	put(e.ActorID)
	put(e.ActorLabel)
	put(e.TargetType)
	put(e.TargetID)
	put(string(e.Payload))
	put(e.IP)
	return []byte(b.String())
}

func hashEvent(e *Event, prevHash string) string {
	sum := sha256.Sum256(canonicalBytes(e, prevHash))
	return hex.EncodeToString(sum[:])
}

// Result is what Verify found.
type Result struct {
	// OK is true when every event examined links correctly.
	OK bool
	// Count is how many events Verify examined before stopping (all of
	// them, when OK).
	Count int
	// BadSeq is the Seq of the first event that failed verification. Zero
	// when OK.
	BadSeq int64
	// Reason explains the failure in a form suitable to show an operator.
	// Empty when OK.
	Reason string
}

// Verify walks the events returned by r.Query(ctx, f) — in the ascending
// Seq order Reader's contract guarantees — and checks that each one's
// PrevHash matches the previous event's Hash (the first event examined is
// checked against anchor instead) and that each one's Hash matches a fresh
// hash of its own content. It stops and reports the first mismatch it
// finds; an empty result set (nothing matches f) is trivially OK.
//
// # The anchor parameter
//
// anchor is the hash the FIRST event Verify examines is expected to chain
// from. Getting this right is the entire point of the parameter, and
// getting it wrong is the single most common way to misuse this function:
//
//   - Pass "" to verify a log from genesis: every event this package ever
//     appended through a Chain, for the range f selects, must still be
//     present, unmodified, and in order. This is the only correct anchor
//     for a range that has never had its oldest entries removed AND that
//     contains no events written before hash-chaining was turned on.
//
//   - A real deployment rarely satisfies both of those forever. Two
//     ordinary situations break a genesis (anchor="") verification over the
//     WHOLE log, and BOTH look identical to "the chain is broken" if you
//     don't know to expect them:
//
//     1. Pre-chain history. A Store that held events before anyone wrapped
//     it in a Chain has rows with PrevHash=="" and Hash=="" that were
//     never meant to be chained at all. Verify has no way to tell "this
//     event predates chaining" apart from "this event's hash was wiped by
//     an attacker" — both look like a hash that doesn't match the event's
//     content. Scope f (e.g. f.Since or f.AfterSeq) to the range that was
//     actually written through a Chain, and use anchor="" for that
//     scoped range — the first chained event's PrevHash is legitimately
//     "" since it had no chained predecessor.
//
//     2. Retention. If old events are ever deleted (MemoryStore's TTL/
//     capacity eviction, or a SQL DELETE a caller runs for its own
//     retention policy), the oldest SURVIVING event's PrevHash still
//     points at the (now-gone) event before it. Verifying the survivors
//     from anchor="" reports that link broken — correctly detecting a
//     removed row, but for a benign, intentional reason. The fix is the
//     same shape as AlertHub's PruneAudit/VerifyAuditChain pair this
//     package's Chain was modeled on: before/while removing the old
//     events, record the Hash of the last one removed (this package does
//     not do this for you — see below), and pass that recorded value as
//     anchor on every future Verify of the surviving range.
//
// This package deliberately does not track or persist anchors itself:
// "what to verify from" after a prune or a pre-chain-history boundary is
// operational state that belongs wherever the caller already keeps its
// own — a settings table, a config value, whatever fits its Store. Verify
// only takes the value as a parameter and uses it exactly as given.
func Verify(ctx context.Context, r Reader, f Filter, anchor string) (Result, error) {
	events, _, err := r.Query(ctx, f)
	if err != nil {
		return Result{}, err
	}

	prev := anchor
	n := 0
	for _, e := range events {
		n++
		if e.PrevHash != prev {
			return Result{
				OK: false, Count: n, BadSeq: e.Seq,
				Reason: "prev_hash does not match the preceding event's hash " +
					"(an event was edited, inserted, or removed — or this range's anchor is wrong; see Verify's doc comment)",
			}, nil
		}
		if want := hashEvent(e, prev); want != e.Hash {
			return Result{
				OK: false, Count: n, BadSeq: e.Seq,
				Reason: "hash does not match the event's own content (the event was edited, " +
					"or it was never chained — see Verify's doc comment)",
			}, nil
		}
		prev = e.Hash
	}
	return Result{OK: true, Count: n}, nil
}
