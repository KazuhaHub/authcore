package passkey

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRegistration_Baseline(t *testing.T) {
	ctx := context.Background()
	svc, creds := newTestService(t, nil)
	handle := handleFor("alice")
	dev := newDevice(testRPID, testOrigin, handle)

	cred := registerDevice(t, ctx, svc, dev, handle, "My Key")

	stored, err := creds.FindByID(ctx, cred.ID)
	if err != nil {
		t.Fatalf("FindByID after registration: %v", err)
	}
	if string(stored.UserHandle) != string(handle) {
		t.Fatalf("stored UserHandle = %q, want %q", stored.UserHandle, handle)
	}
}

func TestRegistration_ChallengeIsSingleUse(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, nil)
	handle := handleFor("alice")
	dev := newDevice(testRPID, testOrigin, handle)

	sessionID, body := signAttestation(t, ctx, svc, dev, handle, "K", "K")
	if _, err := svc.FinishRegistration(ctx, handle, sessionID, jsonRequest(body)); err != nil {
		t.Fatalf("first FinishRegistration: %v", err)
	}
	// Replaying the exact same response against the same (already-consumed)
	// session id must fail: the session is gone, not just the credential
	// re-verified.
	if _, err := svc.FinishRegistration(ctx, handle, sessionID, jsonRequest(body)); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("replayed FinishRegistration = %v, want ErrSessionNotFound", err)
	}
}

func TestRegistration_FailureStillConsumesChallenge(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, nil)
	handle := handleFor("alice")

	sessionID, _, err := svc.BeginRegistration(ctx, handle, "K", "K")
	_ = sessionID
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	_, id, err := svc.BeginRegistration(ctx, handle, "K", "K")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	// Garbage body: FinishRegistration must fail...
	if _, err := svc.FinishRegistration(ctx, handle, id, jsonRequest("not json")); err == nil {
		t.Fatal("FinishRegistration with a garbage body should have failed")
	}
	// ...but the session must already be gone, proving a failed attempt
	// still burns the challenge (no unlimited guessing against one id).
	if _, err := svc.FinishRegistration(ctx, handle, id, jsonRequest("not json")); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("second attempt on the same session = %v, want ErrSessionNotFound", err)
	}
}

func TestRegistration_ChallengeExpires(t *testing.T) {
	ctx := context.Background()
	creds := NewMemoryCredentialStore()
	svc, err := New(Config{
		RPID:          testRPID,
		RPDisplayName: testDisplay,
		RPOrigins:     []string{testOrigin},
		Credentials:   creds,
		Sessions:      NewMemoryStore(10, 20*time.Millisecond),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handle := handleFor("alice")
	dev := newDevice(testRPID, testOrigin, handle)

	sessionID, body := signAttestation(t, ctx, svc, dev, handle, "K", "K")
	time.Sleep(30 * time.Millisecond)

	if _, err := svc.FinishRegistration(ctx, handle, sessionID, jsonRequest(body)); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("FinishRegistration after TTL expiry = %v, want ErrSessionNotFound", err)
	}
}

func TestRegistration_HandleConfusionRejected(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, nil)
	handleA := handleFor("alice")
	handleB := handleFor("bob")
	dev := newDevice(testRPID, testOrigin, handleA)

	// A's ceremony, A's genuine signed response...
	sessionID, body := signAttestation(t, ctx, svc, dev, handleA, "K", "K")
	// ...but finished as B. go-webauthn must reject this (session.UserID
	// was bound to handleA at Begin time), not register the credential
	// under B.
	if _, err := svc.FinishRegistration(ctx, handleB, sessionID, jsonRequest(body)); err == nil {
		t.Fatal("finishing A's registration ceremony as B must fail")
	}
}

// TestRegistration_ExcludesExistingCredentials proves a second registration
// attempt for an authenticator the account already has is rejected by the
// exclusion list this package builds automatically, rather than silently
// creating a duplicate credential.
func TestRegistration_ExcludesExistingCredentials(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, nil)
	handle := handleFor("alice")
	dev := newDevice(testRPID, testOrigin, handle)

	registerDevice(t, ctx, svc, dev, handle, "First")

	// Re-register the SAME authenticator (same virtualwebauthn.Credential,
	// so the same credential ID) under the same handle.
	creation, _, err := svc.BeginRegistration(ctx, handle, "Second", "Second")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	excluded := false
	for _, d := range creation.Response.CredentialExcludeList {
		if string(d.CredentialID) == string(dev.cred.ID) {
			excluded = true
		}
	}
	if !excluded {
		t.Fatal("BeginRegistration must exclude the account's already-registered credential")
	}
}
