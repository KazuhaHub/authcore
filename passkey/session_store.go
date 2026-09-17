package passkey

import (
	"container/list"
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// SessionStore holds the *webauthn.SessionData a Begin call produces until
// the matching Finish call consumes it — the storage go-webauthn's own
// documentation leaves entirely to the caller between the Begin and Finish
// steps of a ceremony (see the Storage section of
// pkg.go.dev/github.com/go-webauthn/webauthn/webauthn). It has nothing to do
// with an HTTP login session: it exists only to span one register-or-login
// ceremony, typically a few seconds, and is discarded once that ceremony
// ends.
//
// An implementation MUST be single-use: Take removes the entry
// unconditionally, whether the ceremony that follows succeeds or the
// authenticator's response fails verification, so a challenge can never be
// replayed and a rejected guess cannot be retried against the same one.
type SessionStore interface {
	// Put stores data under a fresh, unguessable id and returns that id.
	Put(ctx context.Context, data *webauthn.SessionData) (id string, err error)

	// Take returns the session data stored under id and atomically removes
	// it. ok is false when id is unknown, already taken, or expired — these
	// are indistinguishable to the caller by design.
	Take(ctx context.Context, id string) (data *webauthn.SessionData, ok bool)
}

// DefaultSessionTTL and DefaultSessionCapacity are the bounds
// DefaultMemoryStore uses.
const (
	DefaultSessionTTL      = 5 * time.Minute
	DefaultSessionCapacity = 10_000
)

type sessionEntry struct {
	data    *webauthn.SessionData
	expires time.Time
	elem    *list.Element // this entry's node in MemoryStore.order
}

// MemoryStore is the package's default SessionStore: an in-process map
// bounded on two axes so it cannot grow without limit, mirroring
// captcha.MemoryStore elsewhere in this module. Entries older than ttl are
// treated as gone, and the store never holds more than maxItems entries at
// once — once full, the oldest entry (by insertion order) is evicted to make
// room for a new one, expired or not. Both bounds are enforced inline, on
// Put and Take; there is no background goroutine to start, leak, or shut
// down.
//
// MemoryStore is safe for concurrent use.
type MemoryStore struct {
	mu       sync.Mutex
	items    map[string]*sessionEntry
	order    *list.List // ids in insertion order; front is oldest
	ttl      time.Duration
	maxItems int
	now      func() time.Time
}

// NewMemoryStore returns a MemoryStore that keeps at most maxItems entries,
// each expiring ttl after it was put. maxItems <= 0 or ttl <= 0 are replaced
// with the package defaults rather than producing an unbounded store.
func NewMemoryStore(maxItems int, ttl time.Duration) *MemoryStore {
	return newMemoryStore(maxItems, ttl, time.Now)
}

// DefaultMemoryStore returns a MemoryStore using the package's default TTL
// and capacity.
func DefaultMemoryStore() *MemoryStore {
	return NewMemoryStore(DefaultSessionCapacity, DefaultSessionTTL)
}

// newMemoryStore is NewMemoryStore with an injectable clock, for tests.
func newMemoryStore(maxItems int, ttl time.Duration, now func() time.Time) *MemoryStore {
	if maxItems <= 0 {
		maxItems = DefaultSessionCapacity
	}
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	if now == nil {
		now = time.Now
	}
	return &MemoryStore{
		items:    make(map[string]*sessionEntry),
		order:    list.New(),
		ttl:      ttl,
		maxItems: maxItems,
		now:      now,
	}
}

// Put implements SessionStore.
func (s *MemoryStore) Put(_ context.Context, data *webauthn.SessionData) (string, error) {
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)

	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	s.purgeExpiredLocked(now)

	// Capacity cap: evict the oldest entry, expired or not, to make room.
	for len(s.items) >= s.maxItems {
		front := s.order.Front()
		if front == nil {
			break
		}
		s.order.Remove(front)
		delete(s.items, front.Value.(string))
	}

	elem := s.order.PushBack(id)
	s.items[id] = &sessionEntry{data: data, expires: now.Add(s.ttl), elem: elem}
	return id, nil
}

// Take implements SessionStore.
func (s *MemoryStore) Take(_ context.Context, id string) (*webauthn.SessionData, bool) {
	if id == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.items[id]
	if !ok {
		return nil, false
	}
	s.order.Remove(e.elem)
	delete(s.items, id)

	if s.now().After(e.expires) {
		return nil, false
	}
	return e.data, true
}

// Len reports the number of entries currently held, including any that have
// expired but not yet been purged by a Put or a Take. Exposed mainly so
// tests can observe the capacity cap taking effect.
func (s *MemoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// purgeExpiredLocked drops expired entries from the front of order. Entries
// share one ttl and are appended in Put order, so the list stays
// expiry-ordered and this stops at the first entry that has not expired yet.
// Callers must hold s.mu.
func (s *MemoryStore) purgeExpiredLocked(now time.Time) {
	for {
		front := s.order.Front()
		if front == nil {
			return
		}
		id := front.Value.(string)
		e, ok := s.items[id]
		if !ok || now.After(e.expires) {
			s.order.Remove(front)
			delete(s.items, id)
			continue
		}
		return
	}
}
