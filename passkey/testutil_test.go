package passkey

// Test fixtures shared by this package's tests. They use
// github.com/descope/virtualwebauthn to play the role of a real browser +
// authenticator: it signs genuine attestation/assertion responses with a
// generated key, so tests exercise this package's actual cryptographic
// verification path (via go-webauthn) rather than mocking it away.
//
// RP IDs and origins use example.com (RFC 2606), never a real domain.
//
// Every helper here has an error-returning "...E" form plus a *testing.T
// wrapper that Fatals on error. The error-returning forms exist so
// concurrency tests can call them from spawned goroutines without calling
// t.Fatal off the test goroutine, which the testing package does not support.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	testRPID      = "example.com"
	testOrigin    = "https://example.com"
	testAltOrigin = "https://accounts.example.com" // second allowed origin, same RP ID
	testDisplay   = "Example Corp"
)

// device simulates one physical authenticator (a security key or platform
// authenticator) enrolled against one relying party.
type device struct {
	rp   virtualwebauthn.RelyingParty
	auth virtualwebauthn.Authenticator
	cred virtualwebauthn.Credential
}

// newDevice creates a fresh simulated authenticator holding one not-yet-
// registered EC2 credential, scoped to rpID/origin and reporting handle as
// its user handle on every assertion (as a real authenticator would after
// registration bound it to that account).
func newDevice(rpID, origin string, handle []byte) *device {
	d := &device{
		rp:   virtualwebauthn.RelyingParty{Name: testDisplay, ID: rpID, Origin: origin},
		auth: virtualwebauthn.NewAuthenticator(),
		cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
	d.auth.Options.UserHandle = handle
	return d
}

// jsonRequest builds an *http.Request suitable for FinishRegistration /
// FinishLogin from a virtualwebauthn response body.
func jsonRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// newTestService builds a Service against a fresh MemoryCredentialStore, with
// mutate (if non-nil) applied to Config before New is called.
func newTestService(t *testing.T, mutate func(*Config)) (*Service, *MemoryCredentialStore) {
	t.Helper()
	creds := NewMemoryCredentialStore()
	cfg := Config{
		RPID:          testRPID,
		RPDisplayName: testDisplay,
		RPOrigins:     []string{testOrigin, testAltOrigin},
		Credentials:   creds,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	svc, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc, creds
}

// signAttestationE is signAttestation's error-returning form.
func signAttestationE(ctx context.Context, svc *Service, dev *device, handle []byte, name, displayName string, opts ...webauthn.RegistrationOption) (sessionID, body string, err error) {
	creation, id, err := svc.BeginRegistration(ctx, handle, name, displayName, opts...)
	if err != nil {
		return "", "", fmt.Errorf("BeginRegistration: %w", err)
	}
	optsJSON, err := json.Marshal(creation.Response)
	if err != nil {
		return "", "", fmt.Errorf("marshal creation options: %w", err)
	}
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(optsJSON))
	if err != nil {
		return "", "", fmt.Errorf("ParseAttestationOptions: %w", err)
	}
	return id, virtualwebauthn.CreateAttestationResponse(dev.rp, dev.auth, dev.cred, *attOpts), nil
}

// signAttestation drives BeginRegistration and returns the session id plus a
// signed attestation response body from dev, ready for FinishRegistration.
func signAttestation(t *testing.T, ctx context.Context, svc *Service, dev *device, handle []byte, name, displayName string, opts ...webauthn.RegistrationOption) (sessionID string, body string) {
	t.Helper()
	sessionID, body, err := signAttestationE(ctx, svc, dev, handle, name, displayName, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return sessionID, body
}

// registerDeviceE is registerDevice's error-returning form.
func registerDeviceE(ctx context.Context, svc *Service, dev *device, handle []byte, name string) (*webauthn.Credential, error) {
	sessionID, body, err := signAttestationE(ctx, svc, dev, handle, name, name)
	if err != nil {
		return nil, err
	}
	cred, err := svc.FinishRegistration(ctx, handle, sessionID, jsonRequest(body))
	if err != nil {
		return nil, fmt.Errorf("FinishRegistration: %w", err)
	}
	dev.auth.AddCredential(dev.cred)
	return cred, nil
}

// registerDevice runs a full, expected-to-succeed registration ceremony and
// returns the stored credential.
func registerDevice(t *testing.T, ctx context.Context, svc *Service, dev *device, handle []byte, name string) *webauthn.Credential {
	t.Helper()
	cred, err := registerDeviceE(ctx, svc, dev, handle, name)
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

// signAssertionAllowListedE is signAssertionAllowListed's error-returning
// form.
func signAssertionAllowListedE(ctx context.Context, svc *Service, dev *device, handle []byte, opts ...webauthn.LoginOption) (sessionID, body string, err error) {
	assertion, id, err := svc.BeginLogin(ctx, handle, opts...)
	if err != nil {
		return "", "", fmt.Errorf("BeginLogin: %w", err)
	}
	body, err = signAssertionForE(dev, assertion)
	if err != nil {
		return "", "", err
	}
	return id, body, nil
}

// signAssertionAllowListed drives BeginLogin (allow-listed) for handle and
// returns the session id plus a signed assertion response body from dev.
func signAssertionAllowListed(t *testing.T, ctx context.Context, svc *Service, dev *device, handle []byte, opts ...webauthn.LoginOption) (sessionID string, body string) {
	t.Helper()
	sessionID, body, err := signAssertionAllowListedE(ctx, svc, dev, handle, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return sessionID, body
}

// signAssertionDiscoverable drives BeginDiscoverableLogin and returns the
// session id plus a signed assertion response body from dev.
func signAssertionDiscoverable(t *testing.T, ctx context.Context, svc *Service, dev *device, opts ...webauthn.LoginOption) (sessionID string, body string) {
	t.Helper()
	assertion, id, err := svc.BeginDiscoverableLogin(ctx, opts...)
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	return id, signAssertionFor(t, dev, assertion)
}

func signAssertionForE(dev *device, assertion *protocol.CredentialAssertion) (string, error) {
	optsJSON, err := json.Marshal(assertion.Response)
	if err != nil {
		return "", fmt.Errorf("marshal assertion options: %w", err)
	}
	assOpts, err := virtualwebauthn.ParseAssertionOptions(string(optsJSON))
	if err != nil {
		return "", fmt.Errorf("ParseAssertionOptions: %w", err)
	}
	return virtualwebauthn.CreateAssertionResponse(dev.rp, dev.auth, dev.cred, *assOpts), nil
}

func signAssertionFor(t *testing.T, dev *device, assertion *protocol.CredentialAssertion) string {
	t.Helper()
	body, err := signAssertionForE(dev, assertion)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// handleFor returns a fresh, distinguishable opaque user handle for tests.
// Real callers derive this from their own account id; tests just need bytes.
func handleFor(name string) []byte {
	return []byte("handle:" + name)
}
