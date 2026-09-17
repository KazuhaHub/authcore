package passkey

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// BeginRegistration starts a registration (enrollment) ceremony for handle.
//
// handle is the WebAuthn user handle: an opaque byte string, at most 64
// bytes per the spec, that MUST be stable for the lifetime of the account
// and identical across every credential it owns. This package never
// interprets it — only threads it through to the authenticator and back.
// name and displayName populate the two purely cosmetic fields an
// authenticator's own UI may show (WebAuthnName / WebAuthnDisplayName); pass
// the same caller-meaningful string for both if there is no separate
// display name.
//
// Credentials already registered under handle are automatically added to
// the exclusion list (go-webauthn's WithExclusions), so re-registering an
// authenticator the account already has is reported by the browser instead
// of silently creating a duplicate credential. Pass an explicit
// webauthn.WithExclusions in opts to override this default.
//
// The returned string is a session id: hand it back to FinishRegistration
// unchanged, exactly as received.
func (s *Service) BeginRegistration(ctx context.Context, handle []byte, name, displayName string, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, string, error) {
	existing, err := s.creds.FindByUserHandle(ctx, handle)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: loading existing credentials: %w", err)
	}

	full := make([]webauthn.RegistrationOption, 0, len(opts)+1)
	full = append(full, webauthn.WithExclusions(descriptorsOf(existing)))
	full = append(full, opts...)

	u := &identity{handle: handle, name: name, displayName: displayName, creds: credentialsOf(existing)}
	creation, session, err := s.wa.BeginRegistration(u, full...)
	if err != nil {
		return nil, "", err
	}

	id, err := s.sessions.Put(ctx, session)
	if err != nil {
		return nil, "", err
	}
	return creation, id, nil
}

// FinishRegistration completes a registration ceremony started by
// BeginRegistration: it verifies r against the parked session and, on
// success, persists the new credential via CredentialStore.Save before
// returning it.
//
// handle must be the same value passed to the matching BeginRegistration.
// go-webauthn rejects a mismatch itself (it compares handle against the
// user handle baked into the session at Begin time) rather than silently
// registering the credential under a different identity — see the package
// doc.
//
// sessionID is single-use regardless of outcome: a failed verification
// consumes it exactly like a successful one, so a rejected attempt cannot be
// retried against the same challenge.
func (s *Service) FinishRegistration(ctx context.Context, handle []byte, sessionID string, r *http.Request) (*webauthn.Credential, error) {
	session, ok := s.sessions.Take(ctx, sessionID)
	if !ok {
		return nil, ErrSessionNotFound
	}

	u := &identity{handle: handle}
	cred, err := s.wa.FinishRegistration(u, *session, r)
	if err != nil {
		return nil, err
	}

	if err := s.creds.Save(ctx, StoredCredential{UserHandle: handle, Credential: *cred}); err != nil {
		return nil, fmt.Errorf("passkey: saving credential: %w", err)
	}
	return cred, nil
}
