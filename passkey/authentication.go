package passkey

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// LoginResult is what a successful FinishLogin or FinishDiscoverableLogin
// returns.
type LoginResult struct {
	// UserHandle is the opaque handle of the account this login was
	// verified for: the same value passed to BeginLogin, or the value
	// resolved from the credential the authenticator used, for a
	// discoverable ceremony.
	UserHandle []byte

	// Credential is the credential record as it stands after this login.
	// SignCount and Flags reflect this assertion, and this package has
	// already written the record back via CredentialStore.UpdateSignCount
	// by the time this is returned.
	//
	// Credential.Authenticator.CloneWarning is the counter-rollback signal:
	// it is set when the authenticator's reported counter did not advance
	// past the value already on file (and the two are not both simply
	// zero — an authenticator that never implements a counter legitimately
	// reports 0 every time, and that alone is never flagged). This package
	// does not act on it: accepting the login regardless, rejecting it, or
	// logging an alert and continuing is a policy decision left entirely to
	// the caller, made by inspecting this field after a successful call —
	// see the package doc.
	Credential webauthn.Credential
}

// BeginLogin starts an allow-listed login ceremony scoped to a single,
// already-identified handle — e.g. a passkey used as a second factor after
// a password, or a scoped re-authentication. It requires at least one
// credential to already be registered under handle (ErrNoCredentials
// otherwise); for the usernameless "passkey proper" flow where the identity
// is not yet known, use BeginDiscoverableLogin instead.
func (s *Service) BeginLogin(ctx context.Context, handle []byte, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, string, error) {
	stored, err := s.creds.FindByUserHandle(ctx, handle)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: loading credentials: %w", err)
	}
	if len(stored) == 0 {
		return nil, "", ErrNoCredentials
	}

	u := &identity{handle: handle, creds: credentialsOf(stored)}
	assertion, session, err := s.wa.BeginLogin(u, s.withDefaultUV(opts)...)
	if err != nil {
		return nil, "", err
	}

	id, err := s.sessions.Put(ctx, session)
	if err != nil {
		return nil, "", err
	}
	return assertion, id, nil
}

// FinishLogin completes an allow-listed login ceremony started by
// BeginLogin. handle must match the value BeginLogin was called with —
// go-webauthn rejects a mismatch itself (see the package doc). sessionID is
// single-use regardless of outcome, exactly like FinishRegistration.
func (s *Service) FinishLogin(ctx context.Context, handle []byte, sessionID string, r *http.Request) (*LoginResult, error) {
	session, ok := s.sessions.Take(ctx, sessionID)
	if !ok {
		return nil, ErrSessionNotFound
	}

	stored, err := s.creds.FindByUserHandle(ctx, handle)
	if err != nil {
		return nil, fmt.Errorf("passkey: loading credentials: %w", err)
	}

	u := &identity{handle: handle, creds: credentialsOf(stored)}
	cred, err := s.wa.FinishLogin(u, *session, r)
	if err != nil {
		return nil, err
	}

	if err := s.creds.UpdateSignCount(ctx, cred.ID, *cred, s.now()); err != nil {
		return nil, fmt.Errorf("passkey: persisting sign count: %w", err)
	}
	return &LoginResult{UserHandle: handle, Credential: *cred}, nil
}
