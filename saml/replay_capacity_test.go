package saml

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryReplayCache_CapacityPreservesUnexpiredRecords(t *testing.T) {
	for _, capacity := range []int{1, 16, 100} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			cache := NewMemoryReplayCache(capacity)
			now := time.Unix(1000, 0)
			ctx := context.Background()
			for i := 0; i < capacity; i++ {
				if seen, err := cache.SeenOrAdd(ctx, randomID(i), now.Add(time.Minute), now); err != nil || seen {
					t.Fatalf("seed: seen=%v err=%v", seen, err)
				}
			}
			if _, err := cache.SeenOrAdd(ctx, "overflow", now.Add(2*time.Minute), now); !errors.Is(err, ErrReplayCacheFull) {
				t.Fatalf("expected capacity error, got %v", err)
			}
			if cache.Len() != capacity {
				t.Fatalf("cache length=%d want=%d", cache.Len(), capacity)
			}
			for i := 0; i < capacity; i++ {
				if seen, err := cache.SeenOrAdd(ctx, randomID(i), now.Add(time.Minute), now); err != nil || !seen {
					t.Fatalf("unexpired replay record lost: seen=%v err=%v", seen, err)
				}
			}
		})
	}
}

func TestMemoryReplayCache_ConcurrentCapacityAdmission(t *testing.T) {
	cache := NewMemoryReplayCache(1)
	now := time.Unix(1000, 0)
	var admitted atomic.Int32
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Go(func() {
			seen, err := cache.SeenOrAdd(context.Background(), randomID(i), now.Add(time.Minute), now)
			if !seen && err == nil {
				admitted.Add(1)
			}
		})
	}
	workers.Wait()
	if admitted.Load() != 1 || cache.Len() != 1 {
		t.Fatalf("admitted=%d records=%d, want one", admitted.Load(), cache.Len())
	}
}

func TestValidateResponseXML_CapacityPreservesReplayProtection(t *testing.T) {
	sp := newTestSPMaterial(t, "capacity")
	idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)
	provider := newTestProvider(t, sp, idp.idp.Metadata(), func(config *Config) {
		config.AllowIDPInitiated = true
		config.ReplayCache = NewMemoryReplayCache(1)
	})
	first := idp.idpInitiatedResponse(t)
	if _, err := provider.ValidateResponseXML(context.Background(), first, url.URL{}, nil); err != nil {
		t.Fatalf("initial validation: %v", err)
	}
	second := idp.idpInitiatedResponse(t)
	if _, err := provider.ValidateResponseXML(context.Background(), second, url.URL{}, nil); !errors.Is(err, ErrReplayCacheFull) {
		t.Fatalf("new assertion at capacity: %v", err)
	}
	if _, err := provider.ValidateResponseXML(context.Background(), first, url.URL{}, nil); !errors.Is(err, ErrReplayed) {
		t.Fatalf("prior assertion replay at capacity: %v", err)
	}
}
