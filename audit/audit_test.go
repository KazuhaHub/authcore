package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestMarshal(t *testing.T) {
	if got := Marshal(nil); got != nil {
		t.Fatalf("Marshal(nil) = %q, want nil", got)
	}
	got := Marshal(map[string]any{"a": 1})
	var v map[string]any
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatalf("Marshal produced invalid JSON: %v", err)
	}
	if v["a"] != float64(1) {
		t.Fatalf("round-trip = %v, want a=1", v)
	}

	// Marshal must not panic or error out on an unencodable value; it
	// records the failure instead.
	bad := Marshal(make(chan int))
	var errObj map[string]string
	if err := json.Unmarshal(bad, &errObj); err != nil {
		t.Fatalf("Marshal(unencodable) produced invalid JSON: %v", err)
	}
	if errObj["error"] == "" {
		t.Fatalf("Marshal(unencodable) = %q, want an {\"error\":...} payload", bad)
	}
}

func TestBeforeAfter(t *testing.T) {
	got := BeforeAfter(map[string]any{"name": "old"}, map[string]any{"name": "new"})
	var v struct {
		Before map[string]any `json:"before"`
		After  map[string]any `json:"after"`
	}
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatal(err)
	}
	if v.Before["name"] != "old" || v.After["name"] != "new" {
		t.Fatalf("BeforeAfter round-trip = %+v", v)
	}

	// Either side nil is a legitimate create/delete shape.
	got = BeforeAfter(nil, map[string]any{"name": "new"})
	var v2 struct {
		Before *map[string]any `json:"before"`
		After  map[string]any  `json:"after"`
	}
	if err := json.Unmarshal(got, &v2); err != nil {
		t.Fatal(err)
	}
	if v2.Before != nil {
		t.Fatalf("before should marshal to null, got %v", v2.Before)
	}
}

// exercises the end-to-end append/query contract any Store implementation
// (in-memory here, but the same suite is meant to be reusable against a
// SQL adapter in each project) must satisfy.
func TestStoreContract_MemoryStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(0, 0) // defaults

	base := time.Now().UTC()
	events := []*Event{
		{Time: base, Action: "session.create", ActorType: "user", ActorID: "alice", TargetType: "session", TargetID: "s1", IP: "203.0.113.10"},
		{Time: base.Add(time.Minute), Action: "grant.revoke", ActorType: "user", ActorID: "bob", TargetType: "grant", TargetID: "g1", IP: "203.0.113.11"},
		{Time: base.Add(2 * time.Minute), Action: "session.create", ActorType: "system", ActorID: "scheduler", TargetType: "session", TargetID: "s2", IP: "203.0.113.12"},
	}
	for _, e := range events {
		if err := s.Append(ctx, e); err != nil {
			t.Fatalf("append: %v", err)
		}
		if e.Seq == 0 {
			t.Fatal("Append did not assign Seq")
		}
	}

	// No filter: everything, in ascending (insertion) order.
	got, total, err := s.Query(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(got) != 3 {
		t.Fatalf("Query({}) = %d/%d, want 3/3", len(got), total)
	}
	if got[0].ActorID != "alice" || got[2].ActorID != "scheduler" {
		t.Fatalf("Query did not preserve insertion order: %+v", got)
	}

	// ActorType filter.
	got, total, err = s.Query(ctx, Filter{ActorType: "system"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(got) != 1 || got[0].ActorID != "scheduler" {
		t.Fatalf("Query(ActorType=system) = %+v, total=%d", got, total)
	}

	// Action filter.
	got, total, err = s.Query(ctx, Filter{Action: "session.create"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("Query(Action=session.create) = %d/%d, want 2/2", len(got), total)
	}

	// Target filter.
	got, _, err = s.Query(ctx, Filter{TargetType: "grant", TargetID: "g1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ActorID != "bob" {
		t.Fatalf("Query(target=grant/g1) = %+v", got)
	}

	// IP filter.
	got, _, err = s.Query(ctx, Filter{IP: "203.0.113.11"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ActorID != "bob" {
		t.Fatalf("Query(ip) = %+v", got)
	}

	// Time range.
	got, _, err = s.Query(ctx, Filter{Since: base.Add(30 * time.Second), Until: base.Add(90 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ActorID != "bob" {
		t.Fatalf("Query(time range) = %+v", got)
	}

	// AfterSeq cursor (durable-export style).
	got, _, err = s.Query(ctx, Filter{AfterSeq: events[0].Seq})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ActorID != "bob" {
		t.Fatalf("Query(AfterSeq) = %+v", got)
	}

	// Limit/Offset paginate but total ignores them.
	got, total, err = s.Query(ctx, Filter{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("total with pagination = %d, want 3 (pagination must not affect total)", total)
	}
	if len(got) != 1 || got[0].ActorID != "bob" {
		t.Fatalf("Query(Limit=1,Offset=1) = %+v", got)
	}

	// No matches.
	got, total, err = s.Query(ctx, Filter{Action: "nonexistent"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || total != 0 {
		t.Fatalf("Query(no match) = %d/%d, want 0/0", len(got), total)
	}
}

func TestStoreContract_RejectsEmptyAction(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(0, 0)
	if err := s.Append(ctx, &Event{ActorType: "user", ActorID: "x"}); err != ErrActionRequired {
		t.Fatalf("Append with no Action = %v, want ErrActionRequired", err)
	}
}

func TestStoreContract_AppendFillsTimeButNotOverwritesIt(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(0, 0)

	e1 := &Event{Action: "a"}
	if err := s.Append(ctx, e1); err != nil {
		t.Fatal(err)
	}
	if e1.Time.IsZero() {
		t.Fatal("Append left Time zero")
	}

	explicit := time.Date(2020, 5, 1, 0, 0, 0, 0, time.UTC)
	e2 := &Event{Action: "a", Time: explicit}
	if err := s.Append(ctx, e2); err != nil {
		t.Fatal(err)
	}
	if !e2.Time.Equal(explicit) {
		t.Fatalf("Append overwrote an explicit Time: got %v, want %v", e2.Time, explicit)
	}
}

// Query results are copies: mutating one must not corrupt the store.
func TestStoreContract_QueryReturnsCopies(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(0, 0)
	if err := s.Append(ctx, &Event{Action: "a", ActorID: "orig"}); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.Query(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	got[0].ActorID = "mutated"

	got2, _, err := s.Query(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if got2[0].ActorID != "orig" {
		t.Fatalf("mutating a Query result leaked into the store: %+v", got2[0])
	}
}
