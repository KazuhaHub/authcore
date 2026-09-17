// Package ratelimit provides an opaque-key, net/http rate-limiting
// middleware. It is a thin wrapper around github.com/go-chi/httprate for
// the counting algorithm and github.com/go-chi/chi/v5/middleware for
// trusted-proxy-aware client IP extraction; it deliberately does not
// implement its own request counter or X-Forwarded-For parser.
//
// The package has no notion of accounts, users, tenants, or any other
// application concept. Callers identify "who" is being limited either by
// letting the package key on the client IP (the default, with an explicit
// trusted-proxy boundary — see TrustedProxies) or by supplying their own
// KeyFunc that returns an opaque string; the package never interprets that
// string.
//
// It also carries no web-framework dependency: the public API only uses
// net/http types, so it can sit under gin, echo, chi, or plain net/http
// alike. A caller on a framework with its own middleware chain (e.g. gin)
// wraps Limiter.Middleware in a small adapter in their own code; that
// adapter is intentionally not part of this package.
package ratelimit

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
)

// KeyFunc extracts a rate-limit key from a request. The returned string is
// opaque to this package: it might be a client IP, an API token, a hash of
// credentials being verified, or anything else the caller chooses. Callers
// that want to rate-limit "per account" or "per tenant" pass a KeyFunc that
// derives an opaque key from that concept themselves — this package never
// needs to know the concept exists.
type KeyFunc func(r *http.Request) string

// TrustedProxies declares which reverse-proxy hops in front of this server,
// if any, are allowed to set X-Forwarded-For. It controls how the default
// (IP-based) KeyFunc resolves a request's client IP.
//
// The zero value trusts nothing: the client IP is read from the raw TCP
// peer address (http.Request.RemoteAddr) only, and any X-Forwarded-For
// header on the request is ignored entirely. This is the correct default
// for a server that faces the internet directly, and it is also the safe
// fallback for a misconfigured deployment: an empty TrustedProxies can
// never be tricked into trusting a forged header.
//
// Exactly one of CIDRs or Hops should be set once a proxy is in front of
// the server; if both are set, CIDRs takes precedence.
type TrustedProxies struct {
	// CIDRs lists the IP ranges of trusted reverse proxies. The client IP
	// is resolved by walking X-Forwarded-For from right to left and
	// stopping at the first entry that does not fall inside any of these
	// ranges — see middleware.ClientIPFromXFF. Preferred over Hops
	// whenever the proxy's IP ranges are known (most CDNs publish them).
	CIDRs []string

	// Hops is the number of trusted reverse-proxy hops between the client
	// and this server, used only when CIDRs is empty. See
	// middleware.ClientIPFromXFFTrustedProxies for exact semantics and the
	// verification steps to run before relying on a count in production:
	// an under-count leaks the ability to spoof the rate-limit key, an
	// over-count silently disables IP-based limiting.
	Hops int
}

// clientIPMiddleware returns the net/http middleware that resolves the
// trusted client IP into the request context, per tp. A forged
// X-Forwarded-For header can never widen the trust boundary configured
// here: entries outside it are ignored by construction.
func (tp TrustedProxies) clientIPMiddleware() func(http.Handler) http.Handler {
	switch {
	case len(tp.CIDRs) > 0:
		return middleware.ClientIPFromXFF(tp.CIDRs...)
	case tp.Hops > 0:
		return middleware.ClientIPFromXFFTrustedProxies(tp.Hops)
	default:
		return middleware.ClientIPFromRemoteAddr
	}
}

// Config configures a Limiter.
type Config struct {
	// Limit is the number of requests allowed per Window. Required, > 0.
	Limit int

	// Window is the length of the rate-limit window. Required, > 0.
	//
	// The underlying algorithm (httprate) is a weighted sliding window: it
	// blends the previous window's count into the current one in
	// proportion to how much of the current window has elapsed, rather
	// than resetting the count to zero at each window boundary. This
	// avoids the classic fixed-window flaw where a client can burst up to
	// 2x Limit by timing requests around a boundary.
	Window time.Duration

	// LimitFunc, when set, is consulted on every request for a dynamic
	// override of Limit — e.g. a value read from live, hot-reloadable
	// configuration, so an operator changing the rate limit takes effect
	// without a restart. A return value <= 0 falls back to Limit, so a
	// failed or not-yet-loaded config source can never open the gate.
	LimitFunc func() int

	// KeyFunc selects the rate-limit dimension. If nil, requests are keyed
	// by the client IP, resolved according to TrustedProxies.
	KeyFunc KeyFunc

	// TrustedProxies configures how the client IP is derived from
	// X-Forwarded-For when KeyFunc is left nil. Ignored if KeyFunc is set.
	TrustedProxies TrustedProxies

	// OnLimitExceeded, if set, replaces the response written for a
	// rejected request. The default response is 429 Too Many Requests
	// with a Retry-After header set to Window, and no response body
	// beyond the standard http.Error text.
	OnLimitExceeded http.HandlerFunc
}

// Limiter is a net/http middleware that rejects requests exceeding a
// configured rate. It knows nothing about accounts, users, tenants, or
// permissions — only the opaque key it was told to count by.
type Limiter struct {
	limitFunc func() int
	ipWrap    func(http.Handler) http.Handler // nil when Config.KeyFunc was set
	rl        *httprate.RateLimiter
}

// New builds a Limiter from cfg.
//
// It panics if Limit or Window is not positive: a misconfigured limiter
// must fail loudly at startup rather than silently let every request
// through.
func New(cfg Config) *Limiter {
	if cfg.Limit <= 0 {
		panic("ratelimit: Config.Limit must be > 0")
	}
	if cfg.Window <= 0 {
		panic("ratelimit: Config.Window must be > 0")
	}

	l := &Limiter{limitFunc: cfg.LimitFunc}

	keyFn := cfg.KeyFunc
	if keyFn == nil {
		l.ipWrap = cfg.TrustedProxies.clientIPMiddleware()
		keyFn = clientIPKey
	}

	onLimitExceeded := cfg.OnLimitExceeded
	if onLimitExceeded == nil {
		onLimitExceeded = defaultLimitExceeded(cfg.Window)
	}

	l.rl = httprate.NewRateLimiter(cfg.Limit, cfg.Window,
		httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
			return keyFn(r), nil
		}),
		httprate.WithLimitHandler(onLimitExceeded),
	)

	return l
}

// clientIPKey reads the client IP resolved by TrustedProxies.
// clientIPMiddleware (which must run upstream of it) and canonicalizes it
// into a rate-limit key. httprate.CanonicalizeIP buckets an IPv6 client by
// its /64, since a single client typically controls a whole /64 via SLAAC
// and could otherwise rotate addresses within it to dodge the limit.
//
// If no client-IP middleware ran (should not happen via New, but matters
// if Middleware is ever composed unusually), this resolves to "" and every
// such request shares one bucket — strictly more restrictive, never a
// bypass.
func clientIPKey(r *http.Request) string {
	return httprate.CanonicalizeIP(middleware.GetClientIP(r.Context()))
}

func defaultLimitExceeded(window time.Duration) http.HandlerFunc {
	retryAfter := strconv.Itoa(int(window.Seconds()))
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", retryAfter)
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}
}

// Middleware wraps next, rejecting requests over the configured rate with
// the configured (or default) response.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	h := l.rl.Handler(next)

	if l.limitFunc != nil {
		inner := h
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := l.limitFunc(); v > 0 {
				r = r.WithContext(httprate.WithRequestLimit(r.Context(), v))
			}
			inner.ServeHTTP(w, r)
		})
	}

	// The client-IP middleware, when present, must run first so the key
	// function above can read the resolved IP from the request context.
	if l.ipWrap != nil {
		h = l.ipWrap(h)
	}

	return h
}
