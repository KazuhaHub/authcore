package audit

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"
)

// DefaultMemoryStoreTTL and DefaultMemoryStoreCapacity are the bounds
// NewMemoryStore uses when given ttl <= 0 or maxItems <= 0.
//
// The defaults favor a dev/test-sized, short-lived log: a real deployment
// that needs the retention an audit trail typically requires (weeks to
// years, not a day) belongs on a SQL-backed Store, not MemoryStore — see
// the package doc.
const (
	DefaultMemoryStoreTTL      = 24 * time.Hour
	DefaultMemoryStoreCapacity = 100_000
)

// ErrActionRequired is returned by Store.Append (including MemoryStore's
// and Chain's) when the Event being appended has an empty Action.
var ErrActionRequired = errors.New("audit: action required")

// MemoryStore is an in-process Store bounded on two axes so it cannot grow
// without limit: events older than ttl are treated as gone, and the store
// never holds more than maxItems events at once — once full, the oldest
// event is evicted to make room for a new one, even if it has not expired
// yet. Both bounds are enforced without a background goroutine: expiry and
// over-capacity eviction are purged inline on Append (and lazily on Query,
// so a read reflects expiry even between writes). There is nothing to shut
// down and nothing that leaks if the store is simply dropped.
//
// MemoryStore implements HeadReader, so wrapping it in a Chain never pays
// the full-scan fallback.
//
// Safe for concurrent use.
type MemoryStore struct {
	mu       sync.Mutex
	order    *list.List // *Event, ascending Seq; front is oldest
	ttl      time.Duration
	maxItems int
	nextSeq  int64
	now      func() time.Time
}

// NewMemoryStore returns a MemoryStore that keeps at most maxItems events,
// each expiring ttl after it was appended. maxItems <= 0 or ttl <= 0 are
// replaced with the package defaults rather than producing an unbounded
// store.
func NewMemoryStore(maxItems int, ttl time.Duration) *MemoryStore {
	return newMemoryStore(maxItems, ttl, time.Now)
}

// newMemoryStore is NewMemoryStore with an injectable clock, for tests.
func newMemoryStore(maxItems int, ttl time.Duration, now func() time.Time) *MemoryStore {
	if maxItems <= 0 {
		maxItems = DefaultMemoryStoreCapacity
	}
	if ttl <= 0 {
		ttl = DefaultMemoryStoreTTL
	}
	if now == nil {
		now = time.Now
	}
	return &MemoryStore{
		order:    list.New(),
		ttl:      ttl,
		maxItems: maxItems,
		now:      now,
	}
}

// evictExpired drops events from the front (oldest) whose ttl has elapsed
// as of now. Caller must hold mu.
func (m *MemoryStore) evictExpired(now time.Time) {
	for {
		front := m.order.Front()
		if front == nil {
			return
		}
		e := front.Value.(*Event)
		if now.Sub(e.Time) < m.ttl {
			return
		}
		m.order.Remove(front)
	}
}

// Append implements Store.
func (m *MemoryStore) Append(ctx context.Context, e *Event) error {
	if e.Action == "" {
		return ErrActionRequired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now().UTC()
	if e.Time.IsZero() {
		e.Time = now
	}
	m.evictExpired(now)

	m.nextSeq++
	e.Seq = m.nextSeq

	cp := *e
	m.order.PushBack(&cp)

	for m.order.Len() > m.maxItems {
		m.order.Remove(m.order.Front())
	}
	return nil
}

// Head implements HeadReader: the most recently appended, still-live
// event, or nil if the store currently holds none.
func (m *MemoryStore) Head(ctx context.Context) (*Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictExpired(m.now().UTC())
	back := m.order.Back()
	if back == nil {
		return nil, nil
	}
	cp := *back.Value.(*Event)
	return &cp, nil
}

// Query implements Reader.
func (m *MemoryStore) Query(ctx context.Context, f Filter) ([]*Event, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictExpired(m.now().UTC())

	total := 0
	var matched []*Event
	for el := m.order.Front(); el != nil; el = el.Next() {
		e := el.Value.(*Event)
		if !matchFilter(e, f) {
			continue
		}
		total++
		cp := *e
		matched = append(matched, &cp)
	}

	if f.Offset > 0 {
		if f.Offset >= len(matched) {
			matched = nil
		} else {
			matched = matched[f.Offset:]
		}
	}
	if f.Limit > 0 && len(matched) > f.Limit {
		matched = matched[:f.Limit]
	}
	return matched, total, nil
}

func matchFilter(e *Event, f Filter) bool {
	switch {
	case f.ActorType != "" && e.ActorType != f.ActorType:
		return false
	case f.ActorID != "" && e.ActorID != f.ActorID:
		return false
	case f.Action != "" && e.Action != f.Action:
		return false
	case f.TargetType != "" && e.TargetType != f.TargetType:
		return false
	case f.TargetID != "" && e.TargetID != f.TargetID:
		return false
	case f.IP != "" && e.IP != f.IP:
		return false
	case !f.Since.IsZero() && e.Time.Before(f.Since):
		return false
	case !f.Until.IsZero() && e.Time.After(f.Until):
		return false
	case f.AfterSeq != 0 && e.Seq <= f.AfterSeq:
		return false
	}
	return true
}
