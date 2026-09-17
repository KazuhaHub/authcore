package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
//
// # Detecting a Store that silently drops the chain fields
//
// The wrapped Store is required to persist PrevHash/Hash and return them
// unchanged on later reads (see Store.Append's doc comment) — but nothing
// stops a non-compliant adapter from implementing Store, accepting an
// Event with those fields set, and quietly not storing them (e.g. because
// its table has no column for either one). That failure is silent at
// write time: Append returns nil, the chain looks like it's working, and
// the loss is only ever discovered later, by Verify, when it's too late
// to recover the missing hashes.
//
// To catch this early, Chain reads back the event from its own first
// successful Append and compares the stored Hash/PrevHash to what it
// wrote. A mismatch returns ErrStoreDropsChainFields instead of nil,
// right at the first Append, instead of leaving the discovery to whoever
// happens to run Verify much later. This costs exactly one extra read,
// and only once per Chain — every Append after the first (successful, or
// conclusive) check skips it entirely. Pass WithoutStoreIntegrityCheck to
// NewChain to disable it, which only makes sense for a Store already
// known to persist these fields correctly by other means (its own test
// suite, or a battle-tested implementation like MemoryStore) where even
// that single extra read is unwanted.
type Chain struct {
	store              Store
	now                func() time.Time
	skipIntegrityCheck bool

	mu      sync.Mutex
	head    string
	ready   bool
	checked bool // the store-persists-chain-fields check has run conclusively
}

// ChainOption configures a Chain built by NewChain.
type ChainOption func(*Chain)

// WithoutStoreIntegrityCheck disables the one-time read-back check Chain
// otherwise performs after its first successful Append, which confirms
// the wrapped Store actually persists PrevHash/Hash instead of silently
// discarding them (see the Chain doc comment and ErrStoreDropsChainFields).
//
// Only disable this for a Store you already know persists these fields
// correctly through some other means — its own test suite covering this
// exact case, or a well-established implementation such as MemoryStore —
// where the one extra read on the first Append is unwanted overhead. For
// any Store whose persistence of PrevHash/Hash has not been independently
// verified, leave the check enabled: it is exactly the situation it
// exists to catch, and it only ever costs one read, one time.
func WithoutStoreIntegrityCheck() ChainOption {
	return func(c *Chain) { c.skipIntegrityCheck = true }
}

// ErrStoreDropsChainFields is returned by Chain.Append when the wrapped
// Store's Append accepts an Event with PrevHash/Hash set but does not
// actually persist them: reading the just-appended event back (see the
// Chain doc comment) shows different values than what Chain wrote. This
// means the chain is not being recorded at all — Verify will fail on this
// event, and everything appended after it, as soon as anyone runs it, and
// by then the real hashes cannot be recovered.
//
// The fix belongs in the Store: add a place to persist PrevHash and Hash
// (e.g. two more columns on a SQL adapter's table) and have Append save
// whatever value is already set on the *Event it's given — Chain computes
// both fields before calling Store.Append, so the Store only has to store
// and return them, never compute them itself.
//
// See WithoutStoreIntegrityCheck to disable the check that produces this
// error.
var ErrStoreDropsChainFields = errors.New("audit: store does not persist PrevHash/Hash set by Chain (see Chain doc comment and WithoutStoreIntegrityCheck)")

// NewChain wraps store so that Appends made through the returned Chain are
// hash-linked. Wrap the innermost Store once; do not layer multiple Chains
// over the same Store, or Appends made directly against the Store (bypassing
// the Chain) — both leave the chain unable to see every link.
func NewChain(store Store, opts ...ChainOption) *Chain {
	return newChain(store, time.Now, opts...)
}

// newChain is NewChain with an injectable clock, for tests.
func newChain(store Store, now func() time.Time, opts ...ChainOption) *Chain {
	if now == nil {
		now = time.Now
	}
	c := &Chain{store: store, now: now}
	for _, opt := range opts {
		opt(c)
	}
	return c
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

	if !c.checked && !c.skipIntegrityCheck {
		if err := c.checkStorePersistsChainFields(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// checkStorePersistsChainFields is Chain's one-time defense against a
// Store whose Append silently discards PrevHash/Hash instead of
// persisting them — see the Chain doc comment and ErrStoreDropsChainFields
// for what this protects against and why it matters. Called with c.mu
// already held, right after a successful c.store.Append(ctx, want).
//
// It reads back the event that was just appended and compares its
// PrevHash/Hash to what Chain computed and handed to Store.Append. A
// mismatch means the Store dropped the fields, so this returns
// ErrStoreDropsChainFields.
//
// The read itself is inherently best-effort: a Query or HeadReader error,
// or a read that doesn't conclusively identify the event just written
// (see readBack), is not proof the Store is broken, so c.checked is only
// latched once the read is conclusive — an inconclusive attempt is simply
// retried on the next Append, rather than either failing Append on an
// unrelated transient error or never catching a genuinely broken Store
// because one read happened to be inconclusive.
func (c *Chain) checkStorePersistsChainFields(ctx context.Context, want *Event) error {
	got, ok, err := c.readBack(ctx, want.Seq)
	if err != nil || !ok {
		return nil
	}
	c.checked = true
	if got.Hash == want.Hash && got.PrevHash == want.PrevHash {
		return nil
	}
	return fmt.Errorf(
		"%w: appended event Seq=%d with Hash=%q PrevHash=%q, but reading it back returned Hash=%q PrevHash=%q",
		ErrStoreDropsChainFields, want.Seq, want.Hash, want.PrevHash, got.Hash, got.PrevHash)
}

// readBack fetches the event with the given Seq as the Store itself
// stored it, so checkStorePersistsChainFields can compare what Chain
// wrote against what actually made it to storage.
//
// It prefers HeadReader when the Store implements it — mirroring
// loadHead's own preference — since right after our own Append (under
// c.mu, so nothing else can have appended through this Chain in between)
// the head IS the event we just wrote: one targeted read, no query
// filter semantics to depend on. Without HeadReader it falls back to
// Query(Filter{AfterSeq: seq-1, Limit: 1}), which the Reader contract
// (ascending Seq order) already guarantees returns that same event first
// — the same contract Verify itself depends on, so nothing new is being
// assumed of the Store here.
//
// ok is false whenever the read doesn't conclusively identify that exact
// event (no HeadReader/Query error, but an empty result or a Seq that
// doesn't match) — for instance another writer appending directly to the
// Store outside this Chain between our write and our read-back. That is
// reported as inconclusive, not as a dropped-fields failure.
func (c *Chain) readBack(ctx context.Context, seq int64) (*Event, bool, error) {
	if hr, ok := c.store.(HeadReader); ok {
		e, err := hr.Head(ctx)
		if err != nil {
			return nil, false, err
		}
		if e == nil || e.Seq != seq {
			return nil, false, nil
		}
		return e, true, nil
	}
	events, _, err := c.store.Query(ctx, Filter{AfterSeq: seq - 1, Limit: 1})
	if err != nil {
		return nil, false, err
	}
	if len(events) != 1 || events[0].Seq != seq {
		return nil, false, nil
	}
	return events[0], true, nil
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
