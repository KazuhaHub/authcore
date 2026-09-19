package passkey

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// errRefused stands in for an application policy refusal: the shape a consumer
// returns from UpdateSignCount when it will not accept a login.
var errRefused = errors.New("test: the application refused this credential")

// recordingStore wraps a CredentialStore and can refuse the write-back, which is
// how an application says "do not accept this login" from inside the ceremony —
// the only place from which a refusal can also prevent the write.
type recordingStore struct {
	CredentialStore
	refuseAlways  bool
	refuseOnClone bool
	writes        int
}

func (s *recordingStore) UpdateSignCount(ctx context.Context, credentialID []byte, cred webauthn.Credential, usedAt time.Time) error {
	s.writes++
	if s.refuseAlways || (s.refuseOnClone && cred.Authenticator.CloneWarning) {
		return errRefused
	}
	return s.CredentialStore.UpdateSignCount(ctx, credentialID, cred, usedAt)
}

func serviceWithStore(t *testing.T, store CredentialStore) *Service {
	t.Helper()
	svc, err := New(Config{
		RPID:          testRPID,
		RPDisplayName: testDisplay,
		RPOrigins:     []string{testOrigin},
		Credentials:   store,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc
}

// loginPath drives one assertion ceremony through whichever Finish the case is
// about, and returns its result and error.
type loginPath struct {
	name         string
	discoverable bool
}

var loginPaths = []loginPath{
	{name: "allow-listed", discoverable: false},
	{name: "discoverable", discoverable: true},
}

func (p loginPath) begin(t *testing.T, ctx context.Context, svc *Service, dev *device, handle []byte) (string, string) {
	t.Helper()
	if p.discoverable {
		return signAssertionDiscoverable(t, ctx, svc, dev)
	}
	return signAssertionAllowListed(t, ctx, svc, dev, handle)
}

func (p loginPath) finish(ctx context.Context, svc *Service, handle []byte, sessionID, body string) (*LoginResult, error) {
	if p.discoverable {
		return svc.FinishDiscoverableLogin(ctx, sessionID, jsonRequest(body))
	}
	return svc.FinishLogin(ctx, handle, sessionID, jsonRequest(body))
}

// A Store that refuses the write-back must fail the ceremony, on BOTH Finish
// paths. The alternative — logging the refusal and returning a LoginResult
// anyway — is how a consumer's "reject this credential" policy silently becomes
// "accept it", because by then the write has already happened.
func TestWriteBackRefusal_FailsBothFinishPaths(t *testing.T) {
	for _, path := range loginPaths {
		t.Run(path.name, func(t *testing.T) {
			ctx := context.Background()
			store := &recordingStore{CredentialStore: NewMemoryCredentialStore(), refuseAlways: true}
			svc := serviceWithStore(t, store)
			handle := handleFor("alice")
			dev := newDevice(testRPID, testOrigin, handle)
			registerDevice(t, ctx, svc, dev, handle, "Key")

			sessionID, body := path.begin(t, ctx, svc, dev, handle)

			result, err := path.finish(ctx, svc, handle, sessionID, body)
			if store.writes != 1 {
				t.Fatalf("UpdateSignCount called %d times, want exactly 1", store.writes)
			}
			if result != nil {
				t.Fatalf("a refused write-back returned a LoginResult: %+v", result)
			}
			if err == nil {
				t.Fatal("a refused write-back returned no error")
			}
			if !errors.Is(err, errRefused) {
				t.Fatalf("the store's error is not recoverable with errors.Is: %v", err)
			}

			// The challenge was consumed before the refusal, so the same session
			// cannot be retried: a caller must begin again.
			again, err := path.finish(ctx, svc, handle, sessionID, body)
			if again != nil || err == nil {
				t.Fatal("the same session was replayable after a refused write-back")
			}
			if !errors.Is(err, ErrSessionNotFound) {
				t.Fatalf("retry after a refusal = %v, want ErrSessionNotFound", err)
			}
		})
	}
}

// The control. Without it, the test above would still pass if the ceremony failed
// for some unrelated reason before ever reaching the write-back.
func TestWriteBackRefusal_ControlStillSucceeds(t *testing.T) {
	for _, path := range loginPaths {
		t.Run(path.name, func(t *testing.T) {
			ctx := context.Background()
			store := &recordingStore{CredentialStore: NewMemoryCredentialStore()}
			svc := serviceWithStore(t, store)
			handle := handleFor("alice")
			dev := newDevice(testRPID, testOrigin, handle)
			registerDevice(t, ctx, svc, dev, handle, "Key")

			sessionID, body := path.begin(t, ctx, svc, dev, handle)

			result, err := path.finish(ctx, svc, handle, sessionID, body)
			if err != nil {
				t.Fatalf("an accepting store produced an error: %v", err)
			}
			if result == nil {
				t.Fatal("an accepting store returned no result")
			}
			if store.writes != 1 {
				t.Fatalf("UpdateSignCount called %d times, want exactly 1", store.writes)
			}
		})
	}
}

// The refusal that matters in practice is driven by a genuine counter
// regression — the input a real cloned authenticator produces — not by a Store
// that refuses everything. This also pins the "zero writes" direction: a Store
// that refuses BEFORE writing is what keeps the stored record untouched.
func TestWriteBackRefusal_OnCloneWarningFromARealRegression(t *testing.T) {
	ctx := context.Background()
	inner := NewMemoryCredentialStore()
	store := &recordingStore{CredentialStore: inner, refuseOnClone: true}
	svc := serviceWithStore(t, store)
	handle := handleFor("alice")
	dev := newDevice(testRPID, testOrigin, handle)
	cred := registerDevice(t, ctx, svc, dev, handle, "Key")

	// A legitimate login that advances the counter to 5: accepted, and stored.
	dev.cred.Counter = 5
	sessionID, body := signAssertionAllowListed(t, ctx, svc, dev, handle)
	if _, err := svc.FinishLogin(ctx, handle, sessionID, jsonRequest(body)); err != nil {
		t.Fatalf("an advancing counter must be accepted: %v", err)
	}

	// A second copy of the private key: the counter goes backwards, and the
	// Store refuses on seeing CloneWarning.
	dev.cred.Counter = 3
	sessionID, body = signAssertionAllowListed(t, ctx, svc, dev, handle)
	result, err := svc.FinishLogin(ctx, handle, sessionID, jsonRequest(body))
	if result != nil || err == nil || !errors.Is(err, errRefused) {
		t.Fatalf("a counter regression = (%+v, %v), want a refused login", result, err)
	}

	stored, err := inner.FindByID(ctx, cred.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if stored.Credential.Authenticator.SignCount != 5 {
		t.Fatalf("a refused write-back still changed the stored counter: %d", stored.Credential.Authenticator.SignCount)
	}
	if stored.Credential.Authenticator.CloneWarning {
		t.Fatal("a refused write-back still wrote the flagged credential back")
	}
}
