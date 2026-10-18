package saml

import (
	"context"
	"sync"
	"time"
)

// ReplayCache records SAML assertion IDs that have already been accepted,
// so a captured SAMLResponse cannot be replayed for the rest of its
// validity window — something crewjam/saml does not do on its own (see the
// package doc comment).
//
// Implementations must be safe for concurrent use and must make
// SeenOrAdd's check-and-record atomic: if two goroutines call SeenOrAdd
// with the same id at the same time, at most one may receive
// seen == false. That is what turns a concurrent replay (e.g. the same
// captured SAMLResponse posted twice in parallel by an attacker racing the
// legitimate user) into "one succeeds, one is rejected" instead of "both
// succeed".
//
// The package's own use of a ReplayCache never calls SeenOrAdd with a
// zero expiresAt or an empty id.
type ReplayCache interface {
	// SeenOrAdd reports whether id has already been recorded and is not
	// yet expired. If it has not, it is recorded with the given
	// expiresAt and SeenOrAdd returns false. now is the time to evaluate
	// "already expired" against; a real caller passes the current time,
	// tests pass a fixed one.
	//
	// An implementation backed by a store that can fail (a database, a
	// remote cache, ...) returns a non-nil error on such a failure; the
	// caller then decides how to degrade (this package's own
	// Provider.ValidateResponse treats a ReplayCache error as a
	// validation failure — it never silently treats a store error as
	// "not seen").
	SeenOrAdd(ctx context.Context, id string, expiresAt time.Time, now time.Time) (seen bool, err error)
}

// MemoryReplayCache is an in-memory ReplayCache with a hard capacity bound
// and lazy expiry cleanup. At capacity, expired records are removed first.
// If every record is still valid, new IDs receive ErrReplayCacheFull. Accepted
// assertion IDs remain protected until expiry, including under capacity pressure.
//
// A MemoryReplayCache protects a single process. A caller that needs
// replay protection to survive a restart, or to be shared across more
// than one instance of the SP, supplies a ReplayCache backed by their own
// durable store instead (this package's Provider accepts any ReplayCache
// via Config.ReplayCache).
type MemoryReplayCache struct {
	capacity int

	mu    sync.Mutex
	items map[string]time.Time
}

// NewMemoryReplayCache returns a MemoryReplayCache bounded at capacity
// entries. A capacity <= 0 uses DefaultReplayCacheCapacity.
func NewMemoryReplayCache(capacity int) *MemoryReplayCache {
	if capacity <= 0 {
		capacity = DefaultReplayCacheCapacity
	}
	return &MemoryReplayCache{
		capacity: capacity,
		items:    make(map[string]time.Time, min(capacity, 128)),
	}
}

// SeenOrAdd implements ReplayCache. New IDs receive ErrReplayCacheFull when no
// expired record can make room. Existing unexpired IDs still return seen=true.
func (c *MemoryReplayCache) SeenOrAdd(_ context.Context, id string, expiresAt time.Time, now time.Time) (bool, error) {
	if id == "" {
		// The caller (Provider) never does this, but a direct caller of
		// MemoryReplayCache that manages to pass an empty id gets a safe
		// answer rather than a cache entry no one can ever match again.
		return false, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if exp, ok := c.items[id]; ok {
		if now.Before(exp) {
			return true, nil
		}
		// The entry is present but its own TTL has lapsed. This does
		// NOT mean the assertion is safe to accept again — its
		// signature-validity window (NotOnOrAfter) is what determines
		// that, and expiresAt was chosen to cover it plus margin
		// (see Provider.expiryFor). By the time a cache entry's TTL has
		// elapsed, the assertion itself is also past NotOnOrAfter and
		// crewjam/saml's own time-window check rejects it independently
		// — so falling through and overwriting the entry here does not
		// reopen a real replay window, it just reclaims the slot.
	}

	c.sweepExpired(now)
	if len(c.items) >= c.capacity {
		return false, ErrReplayCacheFull
	}
	c.items[id] = expiresAt
	return false, nil
}

// sweepExpired reclaims expired entries when the cache is at capacity.
// Caller holds c.mu.
func (c *MemoryReplayCache) sweepExpired(now time.Time) {
	if len(c.items) < c.capacity {
		return
	}
	// First pass: free, sweep anything already expired.
	for k, exp := range c.items {
		if !now.Before(exp) {
			delete(c.items, k)
		}
	}
}

// Len returns the current number of entries, including any not yet swept
// past their expiry. Exposed for tests and for a caller that wants to
// expose cache occupancy on a status/metrics endpoint.
func (c *MemoryReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}
