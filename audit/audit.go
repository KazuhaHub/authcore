// Package audit provides an application-agnostic activity log: an event
// model, a pluggable Store, and an optional hash-chain decorator for
// tamper-evidence.
//
// # Share mechanism, not policy
//
// This package has no notion of accounts, users, tenants, organizations, or
// roles, and none should ever be added to it. Where the log needs to know
// "who" or "what" was involved, it accepts caller-supplied opaque strings
// (ActorType/ActorID, TargetType/TargetID) and never interprets them beyond
// byte equality. A caller's actor-type vocabulary might be "user", "system",
// "device", "service_account", or anything else; this package neither
// defines nor requires any particular set of values. The public API only
// uses net/http-free, framework-free Go types, so it fits under any web
// framework or none.
//
// Storage is an interface (Store); this package ships one usable in-memory
// implementation (MemoryStore, bounded by both a TTL and an item cap so it
// cannot grow without limit) but no SQL adapter. Real deployments back Store
// with their own table: schemas differ enough across projects (single
// before/after diff vs. a generic JSON detail column, per-tenant partitioning,
// retention policy, indexing needs) that a shared SQL implementation would
// either impose one project's shape on the others or grow enough options to
// become unmaintainable. The SQL adapter belongs in each application.
//
// The hash chain: what it proves and what it does not
//
// Chain and Verify add a SHA-256 hash chain across appended events: each
// event's Hash covers its own content plus the previous event's Hash
// (PrevHash), so the events form a linked list that can be walked and
// recomputed. This proves that a range of stored events has not been
// edited, reordered, or had entries silently removed SINCE they were
// written — PROVIDED the verifier is reading bytes that actually came from
// this package's Append path.
//
// It is NOT protection against a party with direct write access to the
// underlying storage. Anyone who can run arbitrary UPDATE/DELETE/INSERT
// statements against the audit table can recompute a fresh, internally
// consistent chain from any content they like, and Verify has no way to
// distinguish that recomputed chain from a genuine one — the chain only
// covers what is IN the rows, and a full rewrite can put anything there,
// including consistent hashes. Do not present this to anyone as "tamper
// proof" in the sense of resisting a privileged attacker; it is a tripwire
// against accidental corruption, a partial restore, and casual or
// unsophisticated tampering (an operator hand-editing one row through a DB
// GUI, a botched migration), and it gives a later investigation something
// concrete to point at for everything else. A guarantee that survives a
// compromised database requires an external, independent anchor (a
// write-once log, periodic checkpoints published somewhere else, etc.) —
// that is outside this package's scope and is the caller's to build if
// needed.
//
// See Verify's doc comment for the anchor parameter, which exists
// specifically to avoid a false "the chain is broken" report on legacy data
// that predates the chain being turned on, or on data that has had its
// oldest entries pruned.
//
// This package does not log anything itself. Every method that can fail
// returns an error (or, for Store implementations modeled on this
// package's own MemoryStore, simply cannot fail); it is the caller's job to
// decide whether and how an audit-write failure is surfaced, exactly as
// with every other package in this module.
package audit

import (
	"context"
	"encoding/json"
	"time"
)

// Event is one recorded action. A caller building an Event to append sets
// every field it has a value for; Store.Append fills in Seq (always) and
// Time (only if left zero). Chain additionally sets PrevHash and Hash.
type Event struct {
	// Seq is a store-assigned, strictly increasing identifier. It orders
	// events (Query returns them in ascending Seq order, i.e. the order
	// they were appended in) and serves as a resumable cursor (see
	// Filter.AfterSeq). A caller constructing an Event to append leaves
	// this zero; Store.Append overwrites it.
	Seq int64 `json:"seq"`

	// Time is when the action happened. Append sets it to time.Now().UTC()
	// when the caller leaves it zero; a caller that already has an
	// authoritative timestamp (e.g. replaying from another system) may set
	// it explicitly. Time is used for range filtering (Filter.Since/Until)
	// but NOT for ordering — Seq is: a caller-supplied Time can be
	// backdated or coarse-grained, and ordering must stay deterministic
	// regardless.
	Time time.Time `json:"time"`

	// Action names what happened, e.g. "session.create" or "grant.revoke".
	// The vocabulary is entirely the caller's; this package does not
	// interpret it. Store.Append rejects an Event with an empty Action —
	// every recorded line has to say what happened.
	Action string `json:"action"`

	// ActorType and ActorID together identify who performed the action, as
	// an opaque reference into whatever identity model the caller has.
	// ActorType is a caller-chosen label (e.g. "user", "system", "device",
	// "service_account" — this package neither defines nor requires any
	// particular set of values) and ActorID is an opaque string within
	// that type (a numeric id formatted as decimal, a UUID, an API-key
	// name — whatever the caller's model uses). Both may be empty: a
	// request that never authenticated is a legitimate actor to record
	// ("who tried, and failed").
	ActorType string `json:"actor_type,omitempty"`
	ActorID   string `json:"actor_id,omitempty"`

	// ActorLabel is an optional, purely cosmetic caption for display — a
	// username, an email, a device name — captured at write time so the
	// log still reads sensibly after the referenced actor is renamed or
	// deleted. It is never used for filtering or comparison and this
	// package does not validate it.
	ActorLabel string `json:"actor_label,omitempty"`

	// TargetType and TargetID identify what the action was performed on,
	// with the same opacity rules as ActorType/ActorID. Both may be empty
	// for an action with no single target (e.g. a login attempt).
	TargetType string `json:"target_type,omitempty"`
	TargetID   string `json:"target_id,omitempty"`

	// Payload is caller-defined structured detail: a before/after diff, a
	// set of changed field names, redacted request metadata, or anything
	// else worth keeping. nil/empty means no payload was recorded. See
	// Marshal and BeforeAfter for convenient ways to build it.
	Payload json.RawMessage `json:"payload,omitempty"`

	// IP is the request's source address, already resolved by the caller
	// (e.g. through whatever trusted-proxy logic it uses). Empty for a
	// writer acting with no request in flight (a scheduler, a CLI).
	IP string `json:"ip,omitempty"`

	// PrevHash and Hash are set only for an Event appended through a
	// Chain. Both are empty for an Event appended directly to a Store —
	// which is a fully supported, permanent mode of use, not a
	// degraded one; nothing about Store or Query requires a chain.
	PrevHash string `json:"prev_hash,omitempty"`
	Hash     string `json:"hash,omitempty"`
}

// Filter narrows a Query. The zero value matches every event. Every
// non-zero field is combined with AND.
type Filter struct {
	ActorType  string
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	IP         string

	// Since and Until bound Event.Time, inclusively. A zero time.Time
	// means "no bound" on that side.
	Since time.Time
	Until time.Time

	// AfterSeq restricts to events with Seq > AfterSeq. Combined with a
	// stored cursor value, this is what a durable consumer (a SIEM
	// exporter, a replication job) uses to resume "everything new since I
	// last looked" without risking a gap across a restart — the same role
	// AlertHub's AuditSince cursor played, generalized here so any Store
	// gets it for free.
	AfterSeq int64

	// Limit caps the number of returned events; <= 0 means no cap. Offset
	// skips that many matching events before the limit is applied. The
	// total returned by Query ignores both and reflects every event
	// matching the other fields, for building a pagination UI.
	Limit  int
	Offset int
}

// Reader is the read side of Store: what Verify needs, and what a caller
// wanting read-only access (e.g. a report endpoint) should depend on
// instead of the full Store.
type Reader interface {
	// Query returns events matching f in ascending Seq (insertion) order,
	// plus the total count of events matching f's non-pagination fields
	// (i.e. ignoring f.Limit and f.Offset).
	Query(ctx context.Context, f Filter) ([]*Event, int, error)
}

// Store is where events live. Append-only by design: there are
// deliberately no update or delete methods on this interface, matching
// every one of the three source implementations this package unifies —
// an audit log that can be edited through its own API is not an audit
// log. A Store implementation MAY still lose old events to retention
// (MemoryStore does, via TTL and a capacity cap); that is a distinct,
// intentional operation, not a way to edit history, and it is exactly
// the situation Verify's anchor parameter exists for.
type Store interface {
	Reader

	// Append adds e to the log. It assigns e.Seq and, if e.Time is zero,
	// e.Time; both are visible to the caller after Append returns.
	// Implementations must reject an Event with an empty Action.
	// Append must not otherwise mutate e.
	//
	// Store.Append itself never sets, reads, or interprets PrevHash/Hash —
	// computing them is Chain's job, not the Store's. But when a Store is
	// wrapped in a Chain, Chain sets both fields on e BEFORE calling
	// Store.Append, and Append MUST persist them verbatim and return them
	// unchanged from every later Query/HeadReader read of that event,
	// exactly like every other field on Event. A Store whose schema simply
	// has no column for PrevHash/Hash and drops them on the write path is
	// NOT a compliant implementation, even though nothing about that looks
	// wrong at write time: Append still returns nil, the chain still
	// "looks" like it's working, and the loss is only discovered later —
	// by Verify, or by Chain's own one-time startup check (see
	// ErrStoreDropsChainFields) — by which point the real hashes are gone
	// and cannot be reconstructed.
	//
	// A Store's Append CODE does not need to change between chained and
	// unchained use — it never computes, branches on, or requires
	// PrevHash/Hash to be present. But its SCHEMA does need a place to put
	// them if it is ever going to be used underneath a Chain; "no code
	// difference" was never a promise that those two fields could be
	// silently discarded.
	Append(ctx context.Context, e *Event) error
}

// HeadReader is an optional capability a Store may implement to let Chain
// find the current chain head efficiently — the Hash of the most recently
// appended Event, or nil if the store holds none — without scanning the
// whole log. MemoryStore implements it. A Store that does not can still be
// wrapped in a Chain; Chain falls back to a full ascending Query the first
// time it needs the head, once, lazily.
type HeadReader interface {
	Head(ctx context.Context) (*Event, error)
}

// Marshal builds a Payload from an arbitrary Go value (typically a
// map[string]any or a small struct). Marshal never returns an error and
// never panics: a failure to encode is itself recorded, as
// {"error":"..."}, rather than propagated — an audit-formatting mistake
// must not be able to fail (or, worse, silently drop) the write it is
// describing. This mirrors the "never let logging break the operation"
// convention every one of the three source projects independently
// converged on, folded into the shared code once instead of three times.
func Marshal(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		b, _ = json.Marshal(map[string]string{"error": err.Error()})
	}
	return b
}

// BeforeAfter builds a Payload capturing a before/after diff — the shape
// used for administrative changes where the previous and new state are
// both worth keeping. Either value may be nil (e.g. a create has no
// "before", a delete has no "after").
func BeforeAfter(before, after any) json.RawMessage {
	return Marshal(map[string]any{"before": before, "after": after})
}
