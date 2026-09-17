package passkey

import (
	"context"
	"errors"
	"testing"
)

func TestLogin_Baseline(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, nil)
	handle := handleFor("alice")
	dev := newDevice(testRPID, testOrigin, handle)
	registerDevice(t, ctx, svc, dev, handle, "Key")

	sessionID, body := signAssertionAllowListed(t, ctx, svc, dev, handle)
	result, err := svc.FinishLogin(ctx, handle, sessionID, jsonRequest(body))
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if string(result.UserHandle) != string(handle) {
		t.Fatalf("UserHandle = %q, want %q", result.UserHandle, handle)
	}
	if result.Credential.Authenticator.CloneWarning {
		t.Fatal("a clean login must not carry CloneWarning")
	}
}

func TestLogin_NoCredentialsEnrolled(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, nil)
	if _, _, err := svc.BeginLogin(ctx, handleFor("nobody")); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("BeginLogin for a handle with no credentials = %v, want ErrNoCredentials", err)
	}
}

func TestLogin_ChallengeIsSingleUse(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, nil)
	handle := handleFor("alice")
	dev := newDevice(testRPID, testOrigin, handle)
	registerDevice(t, ctx, svc, dev, handle, "Key")

	sessionID, body := signAssertionAllowListed(t, ctx, svc, dev, handle)
	if _, err := svc.FinishLogin(ctx, handle, sessionID, jsonRequest(body)); err != nil {
		t.Fatalf("first FinishLogin: %v", err)
	}
	if _, err := svc.FinishLogin(ctx, handle, sessionID, jsonRequest(body)); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("replayed FinishLogin = %v, want ErrSessionNotFound", err)
	}
}

func TestLogin_HandleConfusionRejected(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, nil)
	handleA := handleFor("alice")
	handleB := handleFor("bob")
	devA := newDevice(testRPID, testOrigin, handleA)
	devB := newDevice(testRPID, testOrigin, handleB)
	registerDevice(t, ctx, svc, devA, handleA, "A's key")
	registerDevice(t, ctx, svc, devB, handleB, "B's key")

	// A's login ceremony, A's genuine signed response...
	sessionID, body := signAssertionAllowListed(t, ctx, svc, devA, handleA)
	// ...finished as B must fail, even though B has a credential of their
	// own -- the session was bound to handleA at Begin time.
	if _, err := svc.FinishLogin(ctx, handleB, sessionID, jsonRequest(body)); err == nil {
		t.Fatal("completing A's login ceremony as B must fail")
	}
}

// TestLogin_OriginMismatch proves a response collected at an origin outside
// Config.RPOrigins is rejected.
func TestLogin_OriginMismatch(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, nil)
	handle := handleFor("alice")
	dev := newDevice(testRPID, testOrigin, handle)
	registerDevice(t, ctx, svc, dev, handle, "Key")

	assertion, sessionID, err := svc.BeginLogin(ctx, handle)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	evil := newDevice(testRPID, "https://evil.example.net", handle)
	evil.cred = dev.cred // same key material, wrong origin claimed by the "browser"
	body := signAssertionFor(t, evil, assertion)

	if _, err := svc.FinishLogin(ctx, handle, sessionID, jsonRequest(body)); err == nil {
		t.Fatal("a response from an unconfigured origin must be rejected")
	}
}

// TestLogin_RPIDMismatch proves a response computed against a different RP
// ID (so a different rpIdHash in authenticatorData) is rejected.
func TestLogin_RPIDMismatch(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, nil)
	handle := handleFor("alice")
	dev := newDevice(testRPID, testOrigin, handle)
	registerDevice(t, ctx, svc, dev, handle, "Key")

	assertion, sessionID, err := svc.BeginLogin(ctx, handle)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	wrongRP := newDevice("not-"+testRPID, testOrigin, handle)
	wrongRP.cred = dev.cred
	body := signAssertionFor(t, wrongRP, assertion)

	if _, err := svc.FinishLogin(ctx, handle, sessionID, jsonRequest(body)); err == nil {
		t.Fatal("a response computed against the wrong RP ID must be rejected")
	}
}

// TestLogin_MultipleOrigins proves a second configured origin under the same
// RP ID is accepted -- the multi-domain deployment case.
func TestLogin_MultipleOrigins(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, nil) // configured with testOrigin AND testAltOrigin
	handle := handleFor("alice")
	dev := newDevice(testRPID, testAltOrigin, handle)
	registerDevice(t, ctx, svc, dev, handle, "Key")

	sessionID, body := signAssertionAllowListed(t, ctx, svc, dev, handle)
	if _, err := svc.FinishLogin(ctx, handle, sessionID, jsonRequest(body)); err != nil {
		t.Fatalf("a response from the second configured origin must be accepted: %v", err)
	}
}

// TestLogin_CounterRollbackIsFlaggedNotBlocked proves a sign-counter
// regression is surfaced as CloneWarning without this package rejecting the
// login itself -- policy is the caller's, per the package doc.
func TestLogin_CounterRollbackIsFlaggedNotBlocked(t *testing.T) {
	ctx := context.Background()
	svc, creds := newTestService(t, nil)
	handle := handleFor("alice")
	dev := newDevice(testRPID, testOrigin, handle)
	cred := registerDevice(t, ctx, svc, dev, handle, "Key")

	// A legitimate login that jumps the counter ahead to 5.
	dev.cred.Counter = 5
	sessionID, body := signAssertionAllowListed(t, ctx, svc, dev, handle)
	result, err := svc.FinishLogin(ctx, handle, sessionID, jsonRequest(body))
	if err != nil {
		t.Fatalf("FinishLogin (counter=5): %v", err)
	}
	if result.Credential.Authenticator.CloneWarning {
		t.Fatal("an advancing counter must not be flagged")
	}
	if result.Credential.Authenticator.SignCount != 5 {
		t.Fatalf("SignCount = %d, want 5", result.Credential.Authenticator.SignCount)
	}

	// A "cloned" replay: the counter goes backwards relative to what is on
	// file (5), simulating a second copy of the credential's private key.
	dev.cred.Counter = 3
	sessionID, body = signAssertionAllowListed(t, ctx, svc, dev, handle)
	result, err = svc.FinishLogin(ctx, handle, sessionID, jsonRequest(body))
	if err != nil {
		t.Fatalf("FinishLogin (counter regression) must NOT return an error -- rejecting is a caller policy decision, not this package's: %v", err)
	}
	if !result.Credential.Authenticator.CloneWarning {
		t.Fatal("a counter that goes backwards must be flagged via CloneWarning")
	}
	// go-webauthn does not advance SignCount when CloneWarning fires -- it
	// stays at the last legitimate value.
	if result.Credential.Authenticator.SignCount != 5 {
		t.Fatalf("SignCount after a rollback = %d, want unchanged 5", result.Credential.Authenticator.SignCount)
	}

	// The write-back to storage happens regardless -- go-webauthn's own
	// storage guidance is that it always happens on a cryptographically
	// successful login. Confirm what's on file reflects it.
	stored, err := creds.FindByID(ctx, cred.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if stored.Credential.Authenticator.SignCount != 5 {
		t.Fatalf("persisted SignCount = %d, want 5", stored.Credential.Authenticator.SignCount)
	}
}

// TestLogin_ZeroCounterIsNeverFlagged proves an authenticator that never
// implements a signature counter (always reports 0) is never treated as a
// clone just because 0 <= 0.
func TestLogin_ZeroCounterIsNeverFlagged(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, nil)
	handle := handleFor("alice")
	dev := newDevice(testRPID, testOrigin, handle)
	registerDevice(t, ctx, svc, dev, handle, "Key") // dev.cred.Counter == 0

	for i := 0; i < 2; i++ {
		sessionID, body := signAssertionAllowListed(t, ctx, svc, dev, handle)
		result, err := svc.FinishLogin(ctx, handle, sessionID, jsonRequest(body))
		if err != nil {
			t.Fatalf("FinishLogin #%d: %v", i, err)
		}
		if result.Credential.Authenticator.CloneWarning {
			t.Fatalf("login #%d: an authenticator reporting counter 0 twice must not be flagged as cloned", i)
		}
	}
}
