package passkey

import (
	"context"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

func discoverableConfig(cfg *Config) {
	cfg.AuthenticatorSelection.ResidentKey = protocol.ResidentKeyRequirementRequired
	cfg.UserVerification = protocol.VerificationRequired
}

func TestDiscoverableLogin_Baseline(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, discoverableConfig)
	handle := handleFor("alice")
	dev := newDevice(testRPID, testOrigin, handle)
	registerDevice(t, ctx, svc, dev, handle, "Passkey")

	sessionID, body := signAssertionDiscoverable(t, ctx, svc, dev)
	result, err := svc.FinishDiscoverableLogin(ctx, sessionID, jsonRequest(body))
	if err != nil {
		t.Fatalf("FinishDiscoverableLogin: %v", err)
	}
	if string(result.UserHandle) != string(handle) {
		t.Fatalf("resolved UserHandle = %q, want %q", result.UserHandle, handle)
	}
}

// TestDiscoverableLogin_ResolvesCorrectAccountAmongMany proves the identity
// resolved by a discoverable login is the one that owns the credential the
// authenticator actually used, not whichever account happens to be looked at
// first.
func TestDiscoverableLogin_ResolvesCorrectAccountAmongMany(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, discoverableConfig)

	handleA, handleB, handleC := handleFor("alice"), handleFor("bob"), handleFor("carol")
	devA := newDevice(testRPID, testOrigin, handleA)
	devB := newDevice(testRPID, testOrigin, handleB)
	devC := newDevice(testRPID, testOrigin, handleC)
	registerDevice(t, ctx, svc, devA, handleA, "A")
	registerDevice(t, ctx, svc, devB, handleB, "B")
	registerDevice(t, ctx, svc, devC, handleC, "C")

	sessionID, body := signAssertionDiscoverable(t, ctx, svc, devB)
	result, err := svc.FinishDiscoverableLogin(ctx, sessionID, jsonRequest(body))
	if err != nil {
		t.Fatalf("FinishDiscoverableLogin: %v", err)
	}
	if string(result.UserHandle) != string(handleB) {
		t.Fatalf("resolved UserHandle = %q, want bob's handle", result.UserHandle)
	}
}

// TestDiscoverableLogin_UnknownCredentialRejected proves a credential ID this
// deployment never registered fails cleanly via CredentialStore's
// ErrCredentialNotFound, rather than resolving to some other account.
func TestDiscoverableLogin_UnknownCredentialRejected(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, discoverableConfig)
	handle := handleFor("alice")
	// A device whose credential is never registered with svc.
	dev := newDevice(testRPID, testOrigin, handle)

	assertion, sessionID, err := svc.BeginDiscoverableLogin(ctx)
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	body := signAssertionFor(t, dev, assertion)
	if _, err := svc.FinishDiscoverableLogin(ctx, sessionID, jsonRequest(body)); err == nil {
		t.Fatal("a discoverable login for an unregistered credential must fail")
	}
}

// TestDiscoverableLogin_UserVerificationRequired proves that, once
// Config.UserVerification is Required, an assertion performed without user
// verification is rejected -- the enforcement gap documented on
// Config.UserVerification.
func TestDiscoverableLogin_UserVerificationRequired(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, discoverableConfig)
	handle := handleFor("alice")
	dev := newDevice(testRPID, testOrigin, handle)
	registerDevice(t, ctx, svc, dev, handle, "Passkey")

	dev.auth.Options.UserNotVerified = true // authenticator did NOT perform UV this time
	sessionID, body := signAssertionDiscoverable(t, ctx, svc, dev)
	if _, err := svc.FinishDiscoverableLogin(ctx, sessionID, jsonRequest(body)); err == nil {
		t.Fatal("a possession-only assertion must be rejected when UserVerification is Required")
	}
}

// TestDiscoverableLogin_UserVerificationPreferredIsNotEnforced documents (via
// a passing test, not just a comment) that the package's default -- Preferred
// -- does NOT reject a possession-only assertion. This is the exact
// footgun Config.UserVerification's doc comment warns about.
func TestDiscoverableLogin_UserVerificationPreferredIsNotEnforced(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, func(cfg *Config) {
		cfg.AuthenticatorSelection.ResidentKey = protocol.ResidentKeyRequirementRequired
		// UserVerification left at the zero value -> defaults to Preferred.
	})
	handle := handleFor("alice")
	dev := newDevice(testRPID, testOrigin, handle)
	registerDevice(t, ctx, svc, dev, handle, "Passkey")

	dev.auth.Options.UserNotVerified = true
	sessionID, body := signAssertionDiscoverable(t, ctx, svc, dev)
	if _, err := svc.FinishDiscoverableLogin(ctx, sessionID, jsonRequest(body)); err != nil {
		t.Fatalf("a possession-only assertion under the default (Preferred) UV must still succeed, got: %v", err)
	}
}

// TestDiscoverableLogin_UpdatesSignCount proves the resolved credential's
// state is persisted through CredentialStore, exactly like the allow-listed
// flow.
func TestDiscoverableLogin_UpdatesSignCount(t *testing.T) {
	ctx := context.Background()
	svc, creds := newTestService(t, discoverableConfig)
	handle := handleFor("alice")
	dev := newDevice(testRPID, testOrigin, handle)
	cred := registerDevice(t, ctx, svc, dev, handle, "Passkey")

	dev.cred.Counter = 9
	sessionID, body := signAssertionDiscoverable(t, ctx, svc, dev)
	if _, err := svc.FinishDiscoverableLogin(ctx, sessionID, jsonRequest(body)); err != nil {
		t.Fatalf("FinishDiscoverableLogin: %v", err)
	}
	stored, err := creds.FindByID(ctx, cred.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if stored.Credential.Authenticator.SignCount != 9 {
		t.Fatalf("persisted SignCount = %d, want 9", stored.Credential.Authenticator.SignCount)
	}
}

// TestDiscoverableLogin_ChallengeIsSingleUse mirrors the allow-listed
// version.
func TestDiscoverableLogin_ChallengeIsSingleUse(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, discoverableConfig)
	handle := handleFor("alice")
	dev := newDevice(testRPID, testOrigin, handle)
	registerDevice(t, ctx, svc, dev, handle, "Passkey")

	sessionID, body := signAssertionDiscoverable(t, ctx, svc, dev)
	if _, err := svc.FinishDiscoverableLogin(ctx, sessionID, jsonRequest(body)); err != nil {
		t.Fatalf("first FinishDiscoverableLogin: %v", err)
	}
	if _, err := svc.FinishDiscoverableLogin(ctx, sessionID, jsonRequest(body)); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("replayed FinishDiscoverableLogin = %v, want ErrSessionNotFound", err)
	}
}
