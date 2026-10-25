package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

func TestConfigurationFingerprintSeparatesVariableSections(t *testing.T) {
	var changed atomic.Bool
	f := newTestIDP(t, func(f *testIDP) {
		f.editMetadata = func(m map[string]any) {
			if changed.Load() {
				m["id_token_signing_alg_values_supported"] = []string{"RS256"}
			} else {
				m["id_token_signing_alg_values_supported"] = []string{"ES256", "RS256"}
			}
		}
	})
	original := testProvider(t, f, nil)
	authorization, code, state := f.authorize(t, original)
	changed.Store(true)
	reconfigured := testProvider(t, f, func(c *Config) { c.Scopes = append(c.Scopes, "ES256") })
	if result, err := reconfigured.Complete(context.Background(), state, code, authorization.State); !errors.Is(err, ErrInvalidState) || result != nil || f.tokenCalls.Load() != 0 {
		t.Fatal("scope/signing-algorithm boundary collision admitted old state", err)
	}
}

func TestInsecureUpstreamContextCannotChangeIssuerTrust(t *testing.T) {
	for _, metadataChanged := range []bool{false, true} {
		t.Run(fmt.Sprint(metadataChanged), func(t *testing.T) {
			f := newTestIDP(t, func(f *testIDP) {
				if metadataChanged {
					f.editMetadata = func(m map[string]any) { m["issuer"] = "https://other.example.test" }
				}
				f.editClaims = func(m map[string]any) { m["iss"] = "https://other.example.test" }
			})
			ctx := coreoidc.InsecureIssuerURLContext(context.Background(), "https://other.example.test")
			p, err := New(ctx, f.config())
			if metadataChanged {
				if !errors.Is(err, ErrDiscovery) || p != nil {
					t.Fatal("context bypassed discovery issuer binding", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer p.CloseIdleConnections()
			a, code, state := f.authorize(t, p)
			if result, err := p.Complete(context.Background(), state, code, a.State); !errors.Is(err, ErrInvalidToken) || result != nil {
				t.Fatal("context bypassed signed issuer binding", err)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRestoredStateAndAlternateSigningAlgorithm(t *testing.T) {
	for _, algorithm := range []string{"RS256", "ES256"} {
		t.Run(algorithm, func(t *testing.T) {
			f := newTestIDP(t, func(f *testIDP) {
				f.methods = nil
				if algorithm == "ES256" {
					key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					if err != nil {
						t.Fatal(err)
					}
					f.signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "fixture-key"))
					if err != nil {
						t.Fatal(err)
					}
					f.publicKey = &key.PublicKey
					f.algorithm = algorithm
				}
			})
			original := testProvider(t, f, nil)
			authorization, code, state := f.authorize(t, original)
			// A durable adapter can reconstruct all four fields in a fresh provider.
			restored := State{Value: authorization.State.Value, Nonce: authorization.State.Nonce, Verifier: authorization.State.Verifier, Configuration: authorization.State.Configuration}
			restarted := testProvider(t, f, nil)
			if result, err := restarted.Complete(context.Background(), state, code, restored); err != nil || result.Subject != "opaque-subject" {
				t.Fatal("restored protocol state failed", err)
			}
		})
	}
}

func TestGoogleIssuerCompatibilityRemainsExplicit(t *testing.T) {
	f := newTestIDP(t, func(f *testIDP) {
		f.issuer = "https://accounts.google.com"
		f.editClaims = func(c map[string]any) { c["iss"] = "accounts.google.com" }
	})
	config := f.config()
	local, _ := url.Parse(f.server.URL)
	original := config.HTTPClient.Transport
	config.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		request := r.Clone(r.Context())
		target := *r.URL
		if target.Host == "accounts.google.com" {
			target.Scheme = local.Scheme
			target.Host = local.Host
		}
		if target.Host != local.Host {
			return nil, ErrUnavailable
		}
		request.URL = &target
		return original.RoundTrip(request)
	})
	p, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer p.CloseIdleConnections()
	a, code, state := f.authorize(t, p)
	result, err := p.Complete(context.Background(), state, code, a.State)
	if err != nil || result.Issuer != "accounts.google.com" || result.ProviderIssuer != "https://accounts.google.com" {
		t.Fatal("verified issuer compatibility was hidden or rejected", err)
	}
}

func testProvider(t *testing.T, f *testIDP, edit func(*Config)) *Provider {
	t.Helper()
	config := f.config()
	if edit != nil {
		edit(&config)
	}
	p, err := New(context.Background(), config)
	if err != nil {
		t.Fatal("provider construction failed", err)
	}
	t.Cleanup(p.CloseIdleConnections)
	return p
}

func TestCodeFlowWithPKCEAndVerifiedClaims(t *testing.T) {
	for _, method := range []AuthMethod{ClientSecretBasic, ClientSecretPost, PublicClient} {
		t.Run(string(method), func(t *testing.T) {
			f := newTestIDP(t, func(f *testIDP) {
				f.methods = []string{string(method)}
				if method == PublicClient {
					f.secret = ""
				}
			})
			p := testProvider(t, f, nil)
			authorization, code, state := f.authorize(t, p)
			result, err := p.Complete(context.Background(), state, code, authorization.State)
			if err != nil || result == nil || result.Subject != "opaque-subject" || result.Issuer != f.issuer || result.ProviderIssuer != f.issuer {
				t.Fatal("verified code flow failed", err)
			}
			var claims struct {
				Email    string `json:"email"`
				Verified bool   `json:"email_verified"`
			}
			if result.Claims(&claims) != nil || claims.Email != "person@example.test" || !claims.Verified {
				t.Fatal("claims were not available")
			}
			if f.tokenCalls.Load() != 1 || f.jwksCalls.Load() < 1 {
				t.Fatal("actual token/JWKS requests not observed")
			}
			if _, err = p.Complete(context.Background(), state, code, authorization.State); !errors.Is(err, ErrExchange) {
				t.Fatal("fixture did not enforce its one-use authorization code", err)
			}
			metadata, err := p.Metadata()
			if err != nil {
				t.Fatal(err)
			}
			metadata.SigningAlgs[0] = "mutated"
			metadata.AuthMethods[0] = "mutated"
			again, _ := p.Metadata()
			if again.SigningAlgs[0] == "mutated" || again.AuthMethods[0] == "mutated" {
				t.Fatal("metadata caller mutated provider configuration")
			}
			for _, value := range []any{f.config(), p, authorization.State, authorization, result} {
				for _, formatted := range []string{fmt.Sprint(value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
					for _, secret := range []string{f.secret, authorization.State.Value, authorization.State.Nonce, authorization.State.Verifier, code, "isolated-access-token", "isolated-refresh-token"} {
						if secret != "" && strings.Contains(formatted, secret) {
							t.Fatal("debug formatting exposed protocol material")
						}
					}
				}
			}
			for _, value := range []any{f.config(), authorization, authorization.State, result} {
				encoded, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range []string{f.secret, authorization.State.Value, authorization.State.Nonce, authorization.State.Verifier, code, "isolated-access-token", "isolated-refresh-token"} {
					if secret != "" && strings.Contains(string(encoded), secret) {
						t.Fatal("JSON serialization exposed protocol material")
					}
				}
			}
		})
	}
}

func TestStateBindingAndPKCEFailures(t *testing.T) {
	f := newTestIDP(t, nil)
	p := testProvider(t, f, nil)
	authorization, code, state := f.authorize(t, p)
	for _, mutate := range []func(*State){func(s *State) { s.Value = "" }, func(s *State) { s.Nonce = "" }, func(s *State) { s.Verifier = "" }, func(s *State) { s.Configuration = "wrong" }} {
		candidate := authorization.State
		mutate(&candidate)
		if result, err := p.Complete(context.Background(), state, code, candidate); !errors.Is(err, ErrInvalidState) || result != nil {
			t.Fatal("invalid stored state accepted", err)
		}
	}
	wrong, _ := randomValue()
	if result, err := p.Complete(context.Background(), wrong, code, authorization.State); !errors.Is(err, ErrInvalidState) || result != nil {
		t.Fatal("mismatched browser state accepted", err)
	}
	other := testProvider(t, f, func(c *Config) { c.RedirectURL = "https://console.example.test/other" })
	if _, err := other.Complete(context.Background(), state, code, authorization.State); !errors.Is(err, ErrInvalidState) {
		t.Fatal("state moved to another callback", err)
	}
	if f.tokenCalls.Load() != 0 {
		t.Fatal("invalid state contacted token endpoint")
	}
	candidate := authorization.State
	candidate.Verifier, _ = randomValue()
	if result, err := p.Complete(context.Background(), state, code, candidate); !errors.Is(err, ErrExchange) || result != nil {
		t.Fatal("provider accepted the wrong PKCE verifier", err)
	}
	for range 16 {
		fresh, err := p.Begin()
		if err != nil || fresh.State.Value == authorization.State.Value || fresh.State.Nonce == authorization.State.Nonce || fresh.State.Verifier == authorization.State.Verifier {
			t.Fatal("protocol values reused")
		}
	}
}

func TestTokenRejections(t *testing.T) {
	cases := []struct {
		name     string
		edit     func(map[string]any)
		category error
	}{
		{"nonce", func(c map[string]any) { c["nonce"] = "wrong" }, ErrNonceMismatch},
		{"missing_nonce", func(c map[string]any) { delete(c, "nonce") }, ErrNonceMismatch},
		{"issuer", func(c map[string]any) { c["iss"] = "https://other.example.test" }, ErrInvalidToken},
		{"audience", func(c map[string]any) { c["aud"] = "another-client" }, ErrInvalidToken},
		{"expiry", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, ErrInvalidToken},
		{"subject", func(c map[string]any) { c["sub"] = "" }, ErrInvalidToken},
		{"access_hash", func(c map[string]any) { c["at_hash"] = "wrong" }, ErrInvalidToken},
		{"authorized_party", func(c map[string]any) { c["azp"] = "another-client" }, ErrInvalidToken},
		{"multi_audience_without_party", func(c map[string]any) { c["aud"] = []string{"fixture-client", "second"} }, ErrInvalidToken},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			f := newTestIDP(t, func(f *testIDP) { f.editClaims = item.edit })
			p := testProvider(t, f, nil)
			authorization, code, state := f.authorize(t, p)
			if result, err := p.Complete(context.Background(), state, code, authorization.State); !errors.Is(err, item.category) || result != nil {
				t.Fatal("invalid token accepted", err)
			}
		})
	}
	f := newTestIDP(t, func(f *testIDP) { f.mode = "tampered-token" })
	p := testProvider(t, f, nil)
	a, code, state := f.authorize(t, p)
	if result, err := p.Complete(context.Background(), state, code, a.State); !errors.Is(err, ErrInvalidToken) || result != nil {
		t.Fatal("tampered JWT accepted", err)
	}
}

func TestClaimsPolicyRemainsWithCaller(t *testing.T) {
	for _, verified := range []any{false, "true", nil} {
		t.Run(fmt.Sprint(verified), func(t *testing.T) {
			f := newTestIDP(t, func(f *testIDP) {
				f.editClaims = func(c map[string]any) {
					c["email_verified"] = verified
					c["aud"] = []string{"fixture-client", "second"}
					c["azp"] = "fixture-client"
				}
			})
			p := testProvider(t, f, nil)
			a, code, state := f.authorize(t, p)
			assertion, err := p.Complete(context.Background(), state, code, a.State)
			if err != nil {
				t.Fatal("protocol layer imposed account-email policy", err)
			}
			var claims struct {
				Verified json.RawMessage `json:"email_verified"`
			}
			if assertion.Claims(&claims) != nil || string(claims.Verified) == "true" {
				t.Fatal("unverified claim became verified")
			}
			if err = assertion.Claims(nil); !errors.Is(err, ErrInvalidClaims) {
				t.Fatal("bad claim destination was not rejected")
			}
		})
	}
}

func TestExchangeDoesNotProbeOrFollowRedirects(t *testing.T) {
	for _, mode := range []string{"lost-token", "redirect-token", "error-body"} {
		t.Run(mode, func(t *testing.T) {
			f := newTestIDP(t, func(f *testIDP) { f.mode = mode })
			p := testProvider(t, f, nil)
			a, code, state := f.authorize(t, p)
			result, err := p.Complete(context.Background(), state, code, a.State)
			if result != nil || !errors.Is(err, ErrExchange) || f.tokenCalls.Load() != 1 || f.captured.Load() != 0 {
				t.Fatal("failed code exchange retried or followed a redirect", err, f.tokenCalls.Load())
			}
			for _, secret := range []string{f.secret, code, a.State.Verifier} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("provider error exposed protocol credentials")
				}
			}
		})
	}
}

func TestResponseLimitsHTTPSAndTimeout(t *testing.T) {
	for _, mode := range []string{"oversized-discovery", "oversized-token", "oversized-jwks"} {
		t.Run(mode, func(t *testing.T) {
			f := newTestIDP(t, func(f *testIDP) { f.mode = mode })
			config := f.config()
			config.MaxResponseBytes = 4096
			p, err := New(context.Background(), config)
			if mode == "oversized-discovery" {
				if !errors.Is(err, ErrDiscovery) || p != nil {
					t.Fatal("oversized valid discovery prefix accepted", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer p.CloseIdleConnections()
			a, code, state := f.authorize(t, p)
			result, err := p.Complete(context.Background(), state, code, a.State)
			expected := ErrExchange
			if mode == "oversized-jwks" {
				expected = ErrInvalidToken
			}
			if result != nil || !errors.Is(err, expected) {
				t.Fatal("oversized response accepted", err)
			}
		})
	}
	for _, mode := range []string{"redirect-discovery", "redirect-http", "hang-discovery"} {
		t.Run(mode, func(t *testing.T) {
			f := newTestIDP(t, func(f *testIDP) { f.mode = mode })
			config := f.config()
			if mode == "hang-discovery" {
				config.Timeout = 50 * time.Millisecond
			}
			started := time.Now()
			p, err := New(context.Background(), config)
			if mode == "redirect-discovery" {
				if err != nil {
					t.Fatal("bounded HTTPS redirect refused", err)
				}
				p.CloseIdleConnections()
				return
			}
			if !errors.Is(err, ErrDiscovery) || p != nil || f.captured.Load() != 0 {
				t.Fatal("unsafe/unbounded discovery accepted", err)
			}
			if mode == "hang-discovery" && time.Since(started) > 2*time.Second {
				t.Fatal("discovery did not respect its timeout")
			}
		})
	}
	f := newTestIDP(t, nil)
	config := f.config()
	config.HTTPClient = nil
	if p, err := New(context.Background(), config); !errors.Is(err, ErrDiscovery) || p != nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
}

func TestConfigurationValidationAndConcurrentFlows(t *testing.T) {
	f := newTestIDP(t, nil)
	for _, edit := range []func(*Config){func(c *Config) { c.IssuerURL = "http://example.test" }, func(c *Config) { c.IssuerURL += "?query=1" }, func(c *Config) { c.RedirectURL = "https://name:secret@example.test/callback" }, func(c *Config) { c.ClientID = "" }, func(c *Config) { c.Timeout = -1 }, func(c *Config) { c.MaxResponseBytes = -1 }, func(c *Config) { c.Scopes = []string{"bad scope"} }} {
		config := f.config()
		edit(&config)
		if p, err := New(context.Background(), config); !errors.Is(err, ErrInvalidConfig) || p != nil {
			t.Fatal("invalid configuration accepted", err)
		}
	}
	for _, edit := range []func(map[string]any){func(m map[string]any) { m["token_endpoint"] = "http://localhost/token" }, func(m map[string]any) { m["id_token_signing_alg_values_supported"] = []string{"none"} }, func(m map[string]any) { m["response_types_supported"] = []string{"id_token"} }} {
		invalid := newTestIDP(t, func(f *testIDP) { f.editMetadata = edit })
		if p, err := New(context.Background(), invalid.config()); !errors.Is(err, ErrDiscovery) || p != nil {
			t.Fatal("unsafe/non-code metadata accepted", err)
		}
	}
	public := newTestIDP(t, func(f *testIDP) { f.secret = "" })
	if p, err := New(context.Background(), public.config()); !errors.Is(err, ErrUnsupportedAuthMethod) || p != nil {
		t.Fatal("public client used an unsupported authentication method", err)
	}
	p := testProvider(t, f, nil)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			authorization, err := p.Begin()
			if err != nil {
				t.Error(err)
				return
			}
			parsed, err := url.Parse(authorization.URL)
			if err != nil || parsed.Query().Get("code_challenge_method") != "S256" {
				t.Error("concurrent authorization failed")
				return
			}
			client := *f.server.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			response, err := client.Get(authorization.URL)
			if err != nil {
				t.Error(err)
				return
			}
			response.Body.Close()
			callback, err := url.Parse(response.Header.Get("Location"))
			if err != nil {
				t.Error(err)
				return
			}
			result, err := p.Complete(context.Background(), callback.Query().Get("state"), callback.Query().Get("code"), authorization.State)
			if err != nil || result == nil {
				t.Error("concurrent code flow failed", err)
			}
		})
	}
	wg.Wait()
	if f.tokenCalls.Load() != 8 {
		t.Fatal("concurrent code requests were lost or repeated")
	}
	var empty *Provider
	if _, err := empty.Begin(); !errors.Is(err, ErrNotConfigured) {
		t.Fatal("nil provider accepted Begin")
	}
	if _, err := empty.Complete(context.Background(), "", "", State{}); !errors.Is(err, ErrNotConfigured) {
		t.Fatal("nil provider accepted Complete")
	}
	empty.CloseIdleConnections()
}
