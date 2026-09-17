package captcha_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/authcore/captcha"
)

// siteverifyStub is a minimal, scriptable siteverify server. handler decides
// the reply; when handler is nil, respond replies with reply (marshaled as
// JSON) and status (default 200 when zero).
type siteverifyStub struct {
	t        *testing.T
	srv      *httptest.Server
	lastForm map[string][]string
}

func newSiteverifyStub(t *testing.T, handler http.HandlerFunc) *siteverifyStub {
	t.Helper()
	stub := &siteverifyStub{t: t}
	stub.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("stub: ParseForm: %v", err)
		}
		stub.lastForm = map[string][]string(r.PostForm)
		handler(w, r)
	}))
	t.Cleanup(stub.srv.Close)
	return stub
}

func jsonReply(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Fatalf("stub: encode reply: %v", err)
	}
}

const testSecret = "s3cr3t-0000000000000000000000-do-not-leak"

func newVerifier(t *testing.T, endpoint string, opts ...captcha.TokenOption) *captcha.TokenVerifier {
	t.Helper()
	allOpts := append([]captcha.TokenOption{captcha.WithEndpoint(endpoint)}, opts...)
	v, err := captcha.NewTokenVerifier(captcha.ProviderTurnstile, testSecret, allOpts...)
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}
	return v
}

// --- success paths, one per provider constant ---

func TestVerify_SuccessPath_AllProviders(t *testing.T) {
	providers := []captcha.Provider{captcha.ProviderTurnstile, captcha.ProviderRecaptcha, captcha.ProviderHCaptcha}
	for _, p := range providers {
		p := p
		t.Run(string(p), func(t *testing.T) {
			stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
				jsonReply(t, w, 0, map[string]any{
					"success":      true,
					"hostname":     "example.com",
					"challenge_ts": "2024-01-02T15:04:05Z",
				})
			})
			v, err := captcha.NewTokenVerifier(p, testSecret, captcha.WithEndpoint(stub.srv.URL))
			if err != nil {
				t.Fatalf("NewTokenVerifier: %v", err)
			}
			res, err := v.Verify(context.Background(), "good-token", "198.51.100.7")
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !res.Success {
				t.Fatalf("Success = false, want true (ErrorCodes=%v)", res.ErrorCodes)
			}
			if res.Hostname != "example.com" {
				t.Fatalf("Hostname = %q, want %q", res.Hostname, "example.com")
			}
			if res.ChallengeTS != "2024-01-02T15:04:05Z" {
				t.Fatalf("ChallengeTS = %q", res.ChallengeTS)
			}
			if res.HostnameMismatch {
				t.Fatal("HostnameMismatch = true on a plain success with no allow list")
			}
		})
	}
}

// --- success:false + provider error codes ---

func TestVerify_ProviderRejectsToken(t *testing.T) {
	stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
		jsonReply(t, w, 0, map[string]any{
			"success":     false,
			"error-codes": []string{"invalid-input-response", "timeout-or-duplicate"},
		})
	})
	v := newVerifier(t, stub.srv.URL)

	res, err := v.Verify(context.Background(), "bad-token", "")
	if err != nil {
		t.Fatalf("Verify returned an error for an ordinary rejected token: %v", err)
	}
	if res.Success {
		t.Fatal("Success = true, want false")
	}
	if res.HostnameMismatch {
		t.Fatal("HostnameMismatch = true, want false — this was a plain rejection, not a hostname problem")
	}
	want := []string{"invalid-input-response", "timeout-or-duplicate"}
	if len(res.ErrorCodes) != len(want) {
		t.Fatalf("ErrorCodes = %v, want %v", res.ErrorCodes, want)
	}
	for i := range want {
		if res.ErrorCodes[i] != want[i] {
			t.Fatalf("ErrorCodes = %v, want %v", res.ErrorCodes, want)
		}
	}
}

// --- hostname pinning: the most important behavior ---

func TestVerify_HostnameMismatch_Rejected(t *testing.T) {
	stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
		jsonReply(t, w, 0, map[string]any{
			"success":  true,
			"hostname": "attacker.example.com",
		})
	})
	v := newVerifier(t, stub.srv.URL, captcha.WithAllowedHostnames("panel.example.com"))

	res, err := v.Verify(context.Background(), "token-solved-elsewhere", "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Success {
		t.Fatal("Success = true for a token solved on a non-allow-listed hostname; hostname pinning did not reject it")
	}
	if !res.HostnameMismatch {
		t.Fatal("HostnameMismatch = false, want true")
	}
	if res.Hostname != "attacker.example.com" {
		t.Fatalf("Hostname = %q, want the provider's reported %q preserved for logging", res.Hostname, "attacker.example.com")
	}
}

func TestVerify_HostnameMatch_CaseInsensitive_Accepted(t *testing.T) {
	stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
		jsonReply(t, w, 0, map[string]any{
			"success":  true,
			"hostname": "Panel.Example.COM",
		})
	})
	v := newVerifier(t, stub.srv.URL, captcha.WithAllowedHostnames("panel.example.com"))

	res, err := v.Verify(context.Background(), "good-token", "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Success {
		t.Fatal("Success = false for a hostname that matches the allow list case-insensitively")
	}
	if res.HostnameMismatch {
		t.Fatal("HostnameMismatch = true on a matching hostname")
	}
}

// --- empty allow list: documented default is "pinning disabled" ---

func TestVerify_EmptyAllowList_SkipsHostnameCheck(t *testing.T) {
	stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
		jsonReply(t, w, 0, map[string]any{
			"success":  true,
			"hostname": "anywhere.example.org",
		})
	})
	// No WithAllowedHostnames call at all.
	v := newVerifier(t, stub.srv.URL)

	res, err := v.Verify(context.Background(), "token-from-anywhere", "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Success {
		t.Fatal("Success = false with no allow list configured; the documented default is to accept any hostname the provider reports")
	}
	if res.HostnameMismatch {
		t.Fatal("HostnameMismatch = true with no allow list configured")
	}
}

// --- network error ---

func TestVerify_NetworkError(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := stub.URL
	stub.Close() // connection refused on any subsequent request to this URL

	v := newVerifier(t, deadURL)
	res, err := v.Verify(context.Background(), "token", "")
	if err == nil {
		t.Fatal("Verify returned nil error for an unreachable server")
	}
	if !errors.Is(err, captcha.ErrNetwork) {
		t.Fatalf("error does not wrap ErrNetwork: %v", err)
	}
	if res.Success {
		t.Fatal("Result.Success = true alongside a non-nil error")
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Fatalf("network error leaks the secret: %v", err)
	}
}

// --- non-200 response ---

func TestVerify_NonOKStatus(t *testing.T) {
	stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("upstream on fire"))
	})
	v := newVerifier(t, stub.srv.URL)

	res, err := v.Verify(context.Background(), "token", "")
	if err == nil {
		t.Fatal("Verify returned nil error for a 500 response")
	}
	if !errors.Is(err, captcha.ErrBadStatus) {
		t.Fatalf("error does not wrap ErrBadStatus: %v", err)
	}
	if res.Success {
		t.Fatal("Result.Success = true alongside a non-nil error")
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Fatalf("status error leaks the secret: %v", err)
	}
}

// --- malformed JSON ---

func TestVerify_MalformedJSON(t *testing.T) {
	stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{not json"))
	})
	v := newVerifier(t, stub.srv.URL)

	res, err := v.Verify(context.Background(), "token", "")
	if err == nil {
		t.Fatal("Verify returned nil error for a malformed JSON body")
	}
	if !errors.Is(err, captcha.ErrDecodeResponse) {
		t.Fatalf("error does not wrap ErrDecodeResponse: %v", err)
	}
	if res.Success {
		t.Fatal("Result.Success = true alongside a non-nil error")
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Fatalf("decode error leaks the secret: %v", err)
	}
}

// --- oversized response body is bounded, not read into memory unbounded ---

func TestVerify_OversizedResponseBodyRejected(t *testing.T) {
	stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Valid JSON prefix followed by far more padding than any genuine
		// siteverify reply would ever contain, simulating a malicious or
		// malfunctioning provider. Verify must give up (bounded read) rather
		// than buffer this all into memory and decode it.
		_, _ = w.Write([]byte(`{"success":true,"hostname":"example.com","pad":"`))
		padding := strings.Repeat("x", 2<<20) // 2 MiB, over the 1 MiB cap
		_, _ = w.Write([]byte(padding))
	})
	v := newVerifier(t, stub.srv.URL)

	res, err := v.Verify(context.Background(), "token", "")
	if err == nil {
		t.Fatal("Verify returned nil error for an oversized response body; the response size is not bounded")
	}
	if !errors.Is(err, captcha.ErrDecodeResponse) {
		t.Fatalf("error does not wrap ErrDecodeResponse: %v", err)
	}
	if res.Success {
		t.Fatal("Result.Success = true alongside an oversized-body error")
	}
}

// --- network timeout ---

func TestVerify_Timeout(t *testing.T) {
	release := make(chan struct{})

	stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
		<-release // hang well past the verifier's timeout
		jsonReply(t, w, 0, map[string]any{"success": true})
	})
	// Registered AFTER newSiteverifyStub, so t.Cleanup's LIFO order runs
	// this BEFORE the stub server's own Close(): the handler must be
	// unblocked first, or Close() would wait forever for its still-active
	// connection.
	t.Cleanup(func() { close(release) })
	v := newVerifier(t, stub.srv.URL, captcha.WithTimeout(50*time.Millisecond))

	start := time.Now()
	res, err := v.Verify(context.Background(), "token", "")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Verify returned nil error for a request that should have timed out")
	}
	if !errors.Is(err, captcha.ErrNetwork) {
		t.Fatalf("error does not wrap ErrNetwork: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error does not wrap context.DeadlineExceeded: %v", err)
	}
	if res.Success {
		t.Fatal("Result.Success = true alongside a timeout error")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Verify took %v, far longer than its 50ms timeout — the timeout was not enforced", elapsed)
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Fatalf("timeout error leaks the secret: %v", err)
	}
}

// --- injected http.Client with no Timeout of its own is still bounded ---

func TestVerify_TimeoutEnforced_EvenWithUntimedInjectedClient(t *testing.T) {
	release := make(chan struct{})

	stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		jsonReply(t, w, 0, map[string]any{"success": true})
	})
	// See the identical comment in TestVerify_Timeout: this must be
	// registered after newSiteverifyStub so it runs before srv.Close().
	t.Cleanup(func() { close(release) })
	// An *http.Client with Timeout left at its zero value (no timeout) —
	// exactly the shape of http.DefaultClient. Verify must still bound the
	// call via context, not rely on the client's own Timeout field.
	untimedClient := &http.Client{}
	v := newVerifier(t, stub.srv.URL, captcha.WithHTTPClient(untimedClient), captcha.WithTimeout(50*time.Millisecond))

	start := time.Now()
	_, err := v.Verify(context.Background(), "token", "")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Verify returned nil error for a request that should have timed out")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Verify took %v with an untimed injected client — the context timeout was not enforced", elapsed)
	}
}

// --- secret never appears in any returned error, across every error path ---

func TestVerify_SecretNeverInErrors(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T) *captcha.TokenVerifier
	}{
		{
			name: "network error",
			setup: func(t *testing.T) *captcha.TokenVerifier {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				u := s.URL
				s.Close()
				return newVerifier(t, u)
			},
		},
		{
			name: "bad status",
			setup: func(t *testing.T) *captcha.TokenVerifier {
				stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusForbidden)
				})
				return newVerifier(t, stub.srv.URL)
			},
		},
		{
			name: "malformed json",
			setup: func(t *testing.T) *captcha.TokenVerifier {
				stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte("<html>nope</html>"))
				})
				return newVerifier(t, stub.srv.URL)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := tc.setup(t)
			_, err := v.Verify(context.Background(), "token", "")
			if err == nil {
				t.Fatal("expected a non-nil error")
			}
			if strings.Contains(err.Error(), testSecret) {
				t.Fatalf("secret leaked into error: %v", err)
			}
		})
	}
}

// --- remoteIP is forwarded to the provider ---

func TestVerify_RemoteIPForwarded(t *testing.T) {
	var gotIP, gotSecret, gotToken string
	stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
		gotIP = r.PostFormValue("remoteip")
		gotSecret = r.PostFormValue("secret")
		gotToken = r.PostFormValue("response")
		jsonReply(t, w, 0, map[string]any{"success": true})
	})
	v := newVerifier(t, stub.srv.URL)

	const wantIP = "203.0.113.42"
	_, err := v.Verify(context.Background(), "the-token", wantIP)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if gotIP != wantIP {
		t.Fatalf("provider received remoteip=%q, want %q", gotIP, wantIP)
	}
	if gotSecret != testSecret {
		t.Fatalf("provider received secret=%q, want %q", gotSecret, testSecret)
	}
	if gotToken != "the-token" {
		t.Fatalf("provider received response=%q, want %q", gotToken, "the-token")
	}
}

func TestVerify_RemoteIPOmittedWhenEmpty(t *testing.T) {
	sawKey := true
	stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, sawKey = r.PostForm["remoteip"]
		jsonReply(t, w, 0, map[string]any{"success": true})
	})
	v := newVerifier(t, stub.srv.URL)

	if _, err := v.Verify(context.Background(), "the-token", ""); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if sawKey {
		t.Fatal("provider form contained a remoteip key for an empty remoteIP argument")
	}
}

// --- empty token short-circuits without a network call ---

func TestVerify_EmptyToken_NoNetworkCall(t *testing.T) {
	called := false
	stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		jsonReply(t, w, 0, map[string]any{"success": true})
	})
	v := newVerifier(t, stub.srv.URL)

	res, err := v.Verify(context.Background(), "", "203.0.113.5")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Success {
		t.Fatal("Success = true for an empty token")
	}
	if called {
		t.Fatal("Verify made a network call for an empty token")
	}
}

// --- constructor validation ---

func TestNewTokenVerifier_EmptySecretRejected(t *testing.T) {
	if _, err := captcha.NewTokenVerifier(captcha.ProviderTurnstile, "  "); err == nil {
		t.Fatal("NewTokenVerifier accepted a blank secret")
	}
}

func TestNewTokenVerifier_UnknownProviderWithoutEndpointRejected(t *testing.T) {
	if _, err := captcha.NewTokenVerifier(captcha.Provider("my-custom-provider"), testSecret); err == nil {
		t.Fatal("NewTokenVerifier accepted an unknown provider with no WithEndpoint override")
	}
}

func TestNewTokenVerifier_CustomEndpoint_UnknownProviderAllowed(t *testing.T) {
	stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
		jsonReply(t, w, 0, map[string]any{"success": true, "hostname": "example.com"})
	})
	v, err := captcha.NewTokenVerifier(captcha.Provider("private-deployment"), testSecret, captcha.WithEndpoint(stub.srv.URL))
	if err != nil {
		t.Fatalf("NewTokenVerifier with a custom endpoint: %v", err)
	}
	res, err := v.Verify(context.Background(), "token", "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Success {
		t.Fatal("Success = false against a custom endpoint that reported success")
	}
}

// --- endpoint constants match the documented providers ---

func TestEndpointConstants(t *testing.T) {
	if captcha.TurnstileEndpoint != "https://challenges.cloudflare.com/turnstile/v0/siteverify" {
		t.Fatalf("TurnstileEndpoint = %q", captcha.TurnstileEndpoint)
	}
	if captcha.RecaptchaEndpoint != "https://www.google.com/recaptcha/api/siteverify" {
		t.Fatalf("RecaptchaEndpoint = %q", captcha.RecaptchaEndpoint)
	}
	if captcha.HCaptchaEndpoint != "https://hcaptcha.com/siteverify" {
		t.Fatalf("HCaptchaEndpoint = %q", captcha.HCaptchaEndpoint)
	}
}

// --- HostOf helper ---

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://panel.example.com:8443/": "panel.example.com",
		"http://Example.COM/path":         "example.com",
		"":                                "",
		"not a url \x7f":                  "",
		"192.0.2.10:9999":                 "",
		"https://198.51.100.20/admin":     "198.51.100.20",
	}
	for in, want := range cases {
		if got := captcha.HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
