package captcha

import (
	"container/list"
	"strings"
	"sync"
	"time"
)

// Store persists challenge answers between Generate and Verify. Its method set
// is intentionally identical to github.com/mojocn/base64Captcha's own Store
// interface, so any value satisfying Store also satisfies that package's Store
// without this file importing it: a caller can swap in a Redis-backed, etcd-backed
// or any other implementation, including a base64Captcha community store, with no
// adapter needed.
//
// clear controls whether the entry is deleted as part of the read. Callers that
// want single-use challenges (the only safe default for a captcha) pass clear
// as true.
type Store interface {
	// Set stores value under id, replacing any existing entry.
	Set(id, value string) error
	// Get returns the value stored under id, or "" if none exists or it has
	// expired. When clear is true the entry is removed as part of the read,
	// regardless of whether it was found.
	Get(id string, clear bool) string
	// Verify reports whether answer matches the value stored under id. When
	// clear is true the entry is removed as part of the check, regardless of
	// whether answer matched — a wrong guess burns the challenge exactly like a
	// right one, so a store configured for single-use never allows brute-forcing
	// the same id twice.
	Verify(id, answer string, clear bool) bool
}

// entry is one stored value plus its expiry and its position in the eviction
// list.
type entry struct {
	value     string
	expiresAt time.Time
	elem      *list.Element // this entry's node in MemoryStore.order
}

// MemoryStore is an in-process Store bounded on two axes so it cannot grow
// without limit: entries older than ttl are treated as gone, and the store
// never holds more than maxItems entries at once — once full, the oldest
// entry is evicted to make room for a new one, even if it has not expired
// yet. Both bounds are enforced without a background goroutine: expired and
// over-capacity entries are purged inline on Set, and a lookup that finds an
// expired entry deletes it too. There is nothing to shut down and nothing
// that leaks if the store is simply dropped.
//
// MemoryStore is the default Store used when a caller does not supply one. It
// is safe for concurrent use.
type MemoryStore struct {
	mu       sync.Mutex
	items    map[string]*entry
	order    *list.List // ids in insertion order; front is oldest
	ttl      time.Duration
	maxItems int
}

// DefaultMemoryStoreTTL and DefaultMemoryStoreCapacity are the bounds
// DefaultMemoryStore uses.
const (
	DefaultMemoryStoreTTL      = 5 * time.Minute
	DefaultMemoryStoreCapacity = 10_000
)

// NewMemoryStore returns a MemoryStore that keeps at most maxItems entries,
// each expiring ttl after it was set. maxItems <= 0 or ttl <= 0 are replaced
// with the package defaults rather than producing an unbounded store.
func NewMemoryStore(maxItems int, ttl time.Duration) *MemoryStore {
	if maxItems <= 0 {
		maxItems = DefaultMemoryStoreCapacity
	}
	if ttl <= 0 {
		ttl = DefaultMemoryStoreTTL
	}
	return &MemoryStore{
		items:    make(map[string]*entry),
		order:    list.New(),
		ttl:      ttl,
		maxItems: maxItems,
	}
}

// DefaultMemoryStore returns a MemoryStore using the package's default TTL and
// capacity.
func DefaultMemoryStore() *MemoryStore {
	return NewMemoryStore(DefaultMemoryStoreCapacity, DefaultMemoryStoreTTL)
}

// Set implements Store.
func (s *MemoryStore) Set(id, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.purgeExpiredLocked(time.Now())

	// Replacing an existing id: drop its old list node first so it doesn't
	// linger as a duplicate.
	if old, ok := s.items[id]; ok {
		s.order.Remove(old.elem)
		delete(s.items, id)
	}

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
	s.items[id] = &entry{value: value, expiresAt: time.Now().Add(s.ttl), elem: elem}
	return nil
}

// Get implements Store.
func (s *MemoryStore) Get(id string, clear bool) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.items[id]
	if !ok {
		return ""
	}
	if time.Now().After(e.expiresAt) {
		s.deleteLocked(id, e)
		return ""
	}
	if clear {
		s.deleteLocked(id, e)
	}
	return e.value
}

// Verify implements Store.
func (s *MemoryStore) Verify(id, answer string, clear bool) bool {
	if id == "" || answer == "" {
		return false
	}
	value := s.Get(id, clear)
	if value == "" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(answer))
}

// Len reports the number of entries currently held, including any that have
// expired but not yet been purged by a Set or a lookup. Exposed mainly so
// tests can observe the capacity cap taking effect.
func (s *MemoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// deleteLocked removes id from both the map and the order list. Callers must
// hold s.mu.
func (s *MemoryStore) deleteLocked(id string, e *entry) {
	s.order.Remove(e.elem)
	delete(s.items, id)
}

// purgeExpiredLocked drops expired entries from the front of order. Entries
// share one ttl and are appended in Set order, so the list stays
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
		if !ok || now.After(e.expiresAt) {
			s.order.Remove(front)
			delete(s.items, id)
			continue
		}
		return
	}
}
