package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// okHandler is the terminal handler used across tests: it records that the
// request reached it by writing 200 OK.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// doRequest fires a single request through h and returns the recorded
// response. remoteAddr and xff may be empty.
func doRequest(h http.Handler, remoteAddr, xff string, extraHeaders map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestOverLimitRejectedThenWindowRecovers exercises the core budget: within
// the window only Limit requests succeed, the next is rejected with 429 and
// Retry-After, and once enough time has passed for the (weighted, sliding)
// window to roll over, a fresh budget is available again.
func TestOverLimitRejectedThenWindowRecovers(t *testing.T) {
	const window = 200 * time.Millisecond
	l := New(Config{Limit: 3, Window: window})
	h := l.Middleware(okHandler)

	const remoteAddr = "203.0.113.5:1111" // RFC 5737 TEST-NET-3

	for i := 0; i < 3; i++ {
		if rec := doRequest(h, remoteAddr, "", nil); rec.Code != http.StatusOK {
			t.Fatalf("request %d: got status %d, want 200", i+1, rec.Code)
		}
	}

	rec := doRequest(h, remoteAddr, "", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th request: got status %d, want 429", rec.Code)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" {
		t.Error("4th request: expected a Retry-After header on rejection, got none")
	}

	// Let the sliding window roll far enough past the burst that the
	// previous window's weighted contribution is negligible.
	//
	// This has to be a real sleep, not an injected clock: github.com/go-chi/
	// httprate's RateLimiter computes both the current window (OnLimit) and
	// the rate calculation (calculateRate) from time.Now().UTC() called
	// directly inside the library, with no seam to override it. httprate
	// does expose WithLimitCounter to swap the counting *backend* (e.g. for
	// Redis), but LimitCounter.Get/Increment are still invoked by the
	// RateLimiter with windows it derived from the real wall clock, so even
	// a custom LimitCounter can't make this deterministic without forking
	// the library. window is kept generous (200ms, slept 3x = 600ms) so the
	// margin comfortably absorbs CI scheduling jitter.
	time.Sleep(3 * window)

	for i := 0; i < 3; i++ {
		if rec := doRequest(h, remoteAddr, "", nil); rec.Code != http.StatusOK {
			t.Fatalf("post-recovery request %d: got status %d, want 200", i+1, rec.Code)
		}
	}
	if rec := doRequest(h, remoteAddr, "", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("post-recovery over-limit request: got status %d, want 429", rec.Code)
	}
}

// TestForgedXFFCannotBypassWithTrustedProxyHops configures a single trusted
// proxy hop and checks that an attacker who varies the entries they inject
// ahead of the proxy-appended entry cannot obtain a fresh rate-limit bucket
// per request — only the proxy-appended (rightmost) entry is trusted.
func TestForgedXFFCannotBypassWithTrustedProxyHops(t *testing.T) {
	l := New(Config{
		Limit:          2,
		Window:         5 * time.Second,
		TrustedProxies: TrustedProxies{Hops: 1},
	})
	h := l.Middleware(okHandler)

	// The rightmost entry (198.51.100.7, RFC 5737 TEST-NET-2) is what the
	// single trusted proxy appended, i.e. the real client. Everything to
	// its left is attacker-controlled and changes on every request.
	forgedPrefixes := []string{
		"192.0.2.9",
		"192.0.2.200, 192.0.2.201",
		"203.0.113.254",
	}

	for i, prefix := range forgedPrefixes[:2] {
		xff := prefix + ", 198.51.100.7"
		if rec := doRequest(h, "192.0.2.1:9999", xff, nil); rec.Code != http.StatusOK {
			t.Fatalf("request %d (forged prefix %q): got status %d, want 200", i+1, prefix, rec.Code)
		}
	}

	// The 3rd request, despite yet another forged prefix, is still the
	// same real client per the trusted (rightmost) entry, so it is
	// rejected rather than granted a fresh bucket.
	xff := forgedPrefixes[2] + ", 198.51.100.7"
	rec := doRequest(h, "192.0.2.1:9999", xff, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd request (forged prefix %q): got status %d, want 429 (forged XFF must not bypass the limit)", forgedPrefixes[2], rec.Code)
	}

	// A different real client (different proxy-appended entry) gets its
	// own bucket.
	rec = doRequest(h, "192.0.2.1:9999", "192.0.2.9, 198.51.100.8", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("different real client: got status %d, want 200", rec.Code)
	}
}

// TestNoTrustedProxiesIgnoresXFF checks the zero-value TrustedProxies
// behavior: the client IP comes only from RemoteAddr, and any
// X-Forwarded-For header — forged or not — has no effect at all.
func TestNoTrustedProxiesIgnoresXFF(t *testing.T) {
	l := New(Config{Limit: 2, Window: 5 * time.Second}) // TrustedProxies zero value
	h := l.Middleware(okHandler)

	const remoteAddr = "192.0.2.50:1234" // RFC 5737 TEST-NET-1

	// Same RemoteAddr, a different forged X-Forwarded-For on every
	// request: since no proxy is trusted, these must still share one
	// bucket, keyed by RemoteAddr alone.
	forged := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}
	for i := 0; i < 2; i++ {
		if rec := doRequest(h, remoteAddr, forged[i], nil); rec.Code != http.StatusOK {
			t.Fatalf("request %d: got status %d, want 200", i+1, rec.Code)
		}
	}
	if rec := doRequest(h, remoteAddr, forged[2], nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd request: got status %d, want 429 (forged XFF must not grant a fresh bucket)", rec.Code)
	}

	// A different RemoteAddr, even reusing an already-seen forged XFF
	// value, is a genuinely different client and gets its own bucket.
	rec := doRequest(h, "192.0.2.51:1234", forged[0], nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("different RemoteAddr: got status %d, want 200", rec.Code)
	}
}

// TestCustomKeyFunc checks that a caller-supplied KeyFunc fully takes over
// keying: two distinct opaque keys are limited independently, regardless of
// the requests' IPs, and the package never inspects what the key means.
func TestCustomKeyFunc(t *testing.T) {
	l := New(Config{
		Limit:  2,
		Window: 5 * time.Second,
		KeyFunc: func(r *http.Request) string {
			return r.Header.Get("X-Client-Key")
		},
	})
	h := l.Middleware(okHandler)

	// Same RemoteAddr for every request: if IP were still in play this
	// would collide, so a pass here demonstrates KeyFunc fully overrides
	// the default IP-based keying.
	const remoteAddr = "203.0.113.9:1"

	for i := 0; i < 2; i++ {
		rec := doRequest(h, remoteAddr, "", map[string]string{"X-Client-Key": "alpha"})
		if rec.Code != http.StatusOK {
			t.Fatalf("alpha request %d: got status %d, want 200", i+1, rec.Code)
		}
	}
	if rec := doRequest(h, remoteAddr, "", map[string]string{"X-Client-Key": "alpha"}); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("alpha 3rd request: got status %d, want 429", rec.Code)
	}

	// A different opaque key, same IP, is an independent budget.
	for i := 0; i < 2; i++ {
		rec := doRequest(h, remoteAddr, "", map[string]string{"X-Client-Key": "beta"})
		if rec.Code != http.StatusOK {
			t.Fatalf("beta request %d: got status %d, want 200", i+1, rec.Code)
		}
	}
}

// TestLimitFuncDynamicOverride checks the hot-reloadable limit override: a
// LimitFunc consulted per request can raise (or lower) the effective quota
// without recreating the Limiter, and a non-positive value falls back to
// the static Config.Limit rather than opening the gate.
func TestLimitFuncDynamicOverride(t *testing.T) {
	dynamicLimit := 1
	l := New(Config{
		Limit:     1,
		Window:    5 * time.Second,
		LimitFunc: func() int { return dynamicLimit },
	})
	h := l.Middleware(okHandler)

	const remoteAddr = "198.51.100.20:1"

	if rec := doRequest(h, remoteAddr, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("1st request: got status %d, want 200", rec.Code)
	}
	if rec := doRequest(h, remoteAddr, "", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("2nd request: got status %d, want 429", rec.Code)
	}

	// Simulate a live config change raising the limit; takes effect
	// immediately, no restart, no new Limiter.
	dynamicLimit = 3
	if rec := doRequest(h, remoteAddr, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("3rd request after raising the limit: got status %d, want 200", rec.Code)
	}

	// A non-positive override must never disable limiting; it falls back
	// to the static Config.Limit (1), which is already exhausted for this
	// key at rate >= 1, so the next request is still rejected.
	dynamicLimit = 0
	if rec := doRequest(h, remoteAddr, "", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("request with a zero override: got status %d, want 429 (must fall back to static Limit, never open the gate)", rec.Code)
	}
}

// TestNewPanicsOnInvalidConfig checks that a misconfigured Limiter fails
// loudly at construction time instead of silently allowing every request.
func TestNewPanicsOnInvalidConfig(t *testing.T) {
	cases := []Config{
		{Limit: 0, Window: time.Second},
		{Limit: -1, Window: time.Second},
		{Limit: 1, Window: 0},
		{Limit: 1, Window: -time.Second},
	}
	for _, cfg := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("New(%+v): expected a panic, got none", cfg)
				}
			}()
			New(cfg)
		}()
	}
}
