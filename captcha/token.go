// This file covers third-party token captcha verification: Cloudflare
// Turnstile, Google reCAPTCHA and hCaptcha all render a client-side widget
// (with a public site key) that hands the caller's page a one-time token,
// and all three are checked the same way server-side — POST the token and a
// secret key to the provider's "siteverify" endpoint, and read back a JSON
// verdict. TokenVerifier is that one HTTP round trip plus the hostname check
// that goes with it, shared by all three providers instead of copied once
// per provider or once per calling service.
//
// TokenVerifier knows nothing about who is presenting the token — no user,
// account, session or request concept. It only ever sees a token, an
// optional client IP to forward, and the provider's reply.
package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Provider names a third-party token captcha service. The zero value is not
// a valid provider on its own — pass WithEndpoint alongside it to verify
// against a custom or self-hosted siteverify-compatible endpoint.
type Provider string

// Known providers, each backed by a public siteverify endpoint below.
const (
	ProviderTurnstile Provider = "turnstile"
	ProviderRecaptcha Provider = "recaptcha"
	ProviderHCaptcha  Provider = "hcaptcha"
)

// Public siteverify endpoints for the known providers. Exported as constants
// so a caller can build on them (e.g. to assert which one a Provider maps
// to) even though NewTokenVerifier already wires them up by default.
const (
	TurnstileEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	RecaptchaEndpoint = "https://www.google.com/recaptcha/api/siteverify"
	HCaptchaEndpoint  = "https://hcaptcha.com/siteverify"
)

// defaultEndpoints maps each known Provider to its public siteverify URL.
var defaultEndpoints = map[Provider]string{
	ProviderTurnstile: TurnstileEndpoint,
	ProviderRecaptcha: RecaptchaEndpoint,
	ProviderHCaptcha:  HCaptchaEndpoint,
}

// DefaultTokenTimeout is the request timeout NewTokenVerifier applies when
// WithTimeout is not given.
const DefaultTokenTimeout = 10 * time.Second

// maxSiteverifyResponseBytes bounds how much of a siteverify response body
// Verify will read. A genuine reply is a few hundred bytes; this is generous
// headroom for that, while still capping memory use if a provider (malicious
// or merely broken) sends back something enormous.
const maxSiteverifyResponseBytes = 1 << 20 // 1 MiB

// Sentinel errors Verify's returned error wraps, so a caller can tell the
// four failure shapes of a siteverify call apart with errors.Is instead of
// string-matching:
//
//   - ErrRequest: the outgoing request could not even be built (a malformed
//     endpoint override). Practically unreachable with the built-in
//     endpoints.
//   - ErrNetwork: the request was sent but no response came back — DNS
//     failure, connection refused, TLS error, or the context's timeout or
//     cancellation firing first. Wraps the underlying network/context error
//     too, so errors.Is(err, context.DeadlineExceeded) also works.
//   - ErrBadStatus: a response came back, but its HTTP status was not 200.
//   - ErrDecodeResponse: the response was 200 but its body was not the JSON
//     shape siteverify replies with.
//
// A provider reply of {"success": false, ...} is deliberately NOT one of
// these — it is not a failure of the verification mechanism, it is the
// mechanism working and reporting a bad token. That comes back as (Result{
// Success: false, ErrorCodes: ...}, nil): see Verify's doc comment.
var (
	ErrRequest        = errors.New("captcha: could not build siteverify request")
	ErrNetwork        = errors.New("captcha: siteverify request failed")
	ErrBadStatus      = errors.New("captcha: siteverify returned a non-200 status")
	ErrDecodeResponse = errors.New("captcha: could not decode siteverify response")
)

// Result is the outcome of one Verify call, carrying enough of the
// provider's reply for the caller to log or branch on without this package
// exposing the raw JSON.
type Result struct {
	// Success is the provider's own verdict on the token, already folded
	// together with the hostname-pinning check below: it is true only when
	// the provider accepted the token AND (hostname pinning is not
	// configured, or the provider's reported hostname is on the allow
	// list). Treat this as the one field to branch on for pass/fail.
	Success bool
	// Hostname is the hostname the provider reports the challenge was
	// solved on. Providers omit this in some configurations (e.g. reCAPTCHA
	// v2 with domain verification turned off), in which case it is "".
	Hostname string
	// ChallengeTS is the provider's own timestamp for when the challenge
	// was solved, exactly as returned (ISO 8601, e.g.
	// "2024-01-02T15:04:05Z"). Not parsed, since callers that want it
	// parsed can do so themselves and this package should not fail Verify
	// over a provider using a slightly different time layout.
	ChallengeTS string
	// ErrorCodes is the provider's own error-codes array, verbatim, present
	// when Success (before hostname pinning) is false. Safe to log: it
	// never contains the secret or the token, only provider-defined
	// short codes like "invalid-input-secret" or "timeout-or-duplicate".
	ErrorCodes []string
	// HostnameMismatch is true when the provider accepted the token but its
	// reported Hostname was not on the configured allow list — the specific
	// case Success=false does not by itself distinguish from an ordinary
	// bad/expired token. See TokenVerifier's WithAllowedHostnames doc for
	// what "allow list" means here, including its empty-list behavior.
	HostnameMismatch bool
}

// TokenOption configures a TokenVerifier built by NewTokenVerifier.
type TokenOption func(*tokenVerifierConfig)

type tokenVerifierConfig struct {
	httpClient   *http.Client
	timeout      time.Duration
	endpoint     string
	allowedHosts []string
}

// WithHTTPClient supplies the *http.Client Verify sends requests with,
// letting a test point it at an httptest.Server (via the client's
// Transport) or a caller share a connection-pooled client across verifiers.
// Unset, NewTokenVerifier builds one of its own with Timeout set from
// WithTimeout (or DefaultTokenTimeout).
//
// Whichever client is in effect, Verify always additionally bounds the
// request with context.WithTimeout using the configured timeout before
// calling it — so even a client with no Timeout of its own (like
// http.DefaultClient) cannot hang a caller forever. Passing an
// http.DefaultClient works but is discouraged: bring your own client so its
// transport-level settings (proxies, connection limits) are under the
// caller's control too.
func WithHTTPClient(c *http.Client) TokenOption {
	return func(cfg *tokenVerifierConfig) { cfg.httpClient = c }
}

// WithTimeout overrides DefaultTokenTimeout as the bound Verify places on
// the whole siteverify round trip, applied via context.WithTimeout
// regardless of which http.Client is in effect (see WithHTTPClient). A
// non-positive value is ignored and the default is kept, so a verifier can
// never end up with no timeout at all.
func WithTimeout(d time.Duration) TokenOption {
	return func(cfg *tokenVerifierConfig) {
		if d > 0 {
			cfg.timeout = d
		}
	}
}

// WithEndpoint overrides the siteverify URL NewTokenVerifier would otherwise
// pick from Provider. Two uses: pointing a verifier at a mock server in
// tests, and pointing it at a private or enterprise siteverify-compatible
// deployment (e.g. hCaptcha Enterprise's dedicated endpoint, or a
// self-hosted Turnstile-compatible service) in production. It is also the
// only way to build a working verifier for a Provider outside the three
// known constants — NewTokenVerifier returns an error for an unknown
// Provider unless this option is also given.
func WithEndpoint(rawURL string) TokenOption {
	return func(cfg *tokenVerifierConfig) { cfg.endpoint = strings.TrimSpace(rawURL) }
}

// WithAllowedHostnames turns on hostname pinning: after the provider accepts
// a token, its reported Hostname must case-insensitively match one of hosts,
// or Verify reports Success: false, HostnameMismatch: true. This is the
// defense against a token solved on a different site that happens to share
// this site key/secret being replayed against this caller.
//
// Chosen default — an EMPTY or never-given host list DISABLES this check
// entirely, and Verify accepts whatever hostname (or lack of one) the
// provider reports. This mirrors both call sites this package's token
// verification was consolidated from, which made the same choice for the
// same reason: a hostname to pin against comes from the caller's own
// configured public URL, and a deployment that has not configured one
// (or configured it wrong) must not be locked out of login entirely by a
// captcha check silently rejecting every token. The tradeoff this makes
// is explicit: with no allow list configured, hostname pinning provides
// NO protection against cross-site token replay — a caller that has a
// known origin should always call WithAllowedHostnames rather than rely on
// this default.
//
// Empty strings in hosts are ignored; passing only empty strings (or none at
// all) is equivalent to not calling this option.
func WithAllowedHostnames(hosts ...string) TokenOption {
	return func(cfg *tokenVerifierConfig) {
		for _, h := range hosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h != "" {
				cfg.allowedHosts = append(cfg.allowedHosts, h)
			}
		}
	}
}

// HostOf extracts the bare hostname (no scheme, no port) from a base URL
// like "https://panel.example.com:8443/". Returns "" for an empty or
// unparseable URL. It exists so a caller can build the WithAllowedHostnames
// list straight from a configured public base URL without duplicating this
// parsing at each call site.
func HostOf(baseURL string) string {
	b := strings.TrimSpace(baseURL)
	if b == "" {
		return ""
	}
	u, err := url.Parse(b)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// TokenVerifier checks third-party captcha tokens against one provider's
// siteverify endpoint. Build one with NewTokenVerifier; the zero value is
// not usable (it has no endpoint and no secret).
type TokenVerifier struct {
	provider     Provider
	endpoint     string
	secret       string
	httpClient   *http.Client
	timeout      time.Duration
	allowedHosts []string
}

// NewTokenVerifier builds a TokenVerifier for provider, authenticating to
// its siteverify endpoint with secret. secret must be non-empty. provider
// must be one of the known constants (ProviderTurnstile, ProviderRecaptcha,
// ProviderHCaptcha) unless WithEndpoint is also given, in which case
// provider is only used as a label — the endpoint it names is never
// resolved.
func NewTokenVerifier(provider Provider, secret string, opts ...TokenOption) (*TokenVerifier, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil, errors.New("captcha: token verifier requires a non-empty secret")
	}

	cfg := tokenVerifierConfig{timeout: DefaultTokenTimeout}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.timeout <= 0 {
		cfg.timeout = DefaultTokenTimeout
	}

	endpoint := cfg.endpoint
	if endpoint == "" {
		known, ok := defaultEndpoints[provider]
		if !ok {
			return nil, fmt.Errorf("captcha: unknown provider %q and no endpoint override given (use WithEndpoint)", provider)
		}
		endpoint = known
	}

	httpClient := cfg.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: cfg.timeout}
	}

	return &TokenVerifier{
		provider:     provider,
		endpoint:     endpoint,
		secret:       secret,
		httpClient:   httpClient,
		timeout:      cfg.timeout,
		allowedHosts: cfg.allowedHosts,
	}, nil
}

// siteverifyResponse is the JSON shape shared by Turnstile, reCAPTCHA and
// hCaptcha's siteverify replies.
type siteverifyResponse struct {
	Success     bool     `json:"success"`
	Hostname    string   `json:"hostname"`
	ChallengeTS string   `json:"challenge_ts"`
	ErrorCodes  []string `json:"error-codes"`
}

// Verify POSTs token (and remoteIP, if given) to the provider's siteverify
// endpoint and reports what came back.
//
// Two different things can make this fail, and they are deliberately not
// confused with each other:
//
//   - A non-nil error means the CHECK ITSELF could not be completed: the
//     request could not be built (ErrRequest), the network call failed or
//     timed out (ErrNetwork), the response status was not 200 (ErrBadStatus),
//     or the 200 response body was not valid siteverify JSON
//     (ErrDecodeResponse). A caller should treat this as "unknown", not as
//     "rejected" — fail closed (do not treat the captcha as solved), but do
//     not report it to the end user the same way as a wrong answer, since a
//     retry by the same user is unlikely to help while the provider is
//     unreachable.
//   - A nil error with Result.Success == false means the check completed
//     and the token was rejected — either by the provider itself (see
//     Result.ErrorCodes) or by hostname pinning (see
//     Result.HostnameMismatch). This is an ordinary "bad captcha", safe to
//     surface to the end user as such.
//
// An empty token is always (Result{}, nil) without making a network call —
// there is nothing for the provider to check.
//
// secret is never included in the returned error, in Result, or anywhere
// else Verify writes to — a caller can log a Verify error directly.
func (v *TokenVerifier) Verify(ctx context.Context, token, remoteIP string) (Result, error) {
	if token == "" {
		return Result{}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	form := url.Values{"secret": {v.secret}, "response": {token}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrRequest, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrNetwork, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("%w: %d %s", ErrBadStatus, resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	var out siteverifyResponse
	body := io.LimitReader(resp.Body, maxSiteverifyResponseBytes)
	if err := json.NewDecoder(body).Decode(&out); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrDecodeResponse, err)
	}

	result := Result{
		Success:     out.Success,
		Hostname:    out.Hostname,
		ChallengeTS: out.ChallengeTS,
		ErrorCodes:  out.ErrorCodes,
	}
	if !result.Success {
		return result, nil
	}

	// Hostname pinning: see WithAllowedHostnames for the empty-list
	// behavior and the reasoning behind it. Leniently skipped (like the two
	// call sites this was consolidated from) when the provider itself did
	// not report a hostname, since some providers omit it depending on how
	// the site key was configured on the provider's side, and pinning
	// cannot check what was never reported.
	if len(v.allowedHosts) > 0 && result.Hostname != "" {
		if !hostAllowed(result.Hostname, v.allowedHosts) {
			result.Success = false
			result.HostnameMismatch = true
		}
	}

	return result, nil
}

// hostAllowed reports whether host case-insensitively matches one of
// allowed. Both sides are expected already-lowercased by their respective
// callers (WithAllowedHostnames, the provider's own JSON), but this compares
// with EqualFold rather than assuming that, since a provider is free to
// return mixed case.
func hostAllowed(host string, allowed []string) bool {
	for _, h := range allowed {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}
