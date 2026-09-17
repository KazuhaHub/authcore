package passkey

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// BeginDiscoverableLogin starts a usernameless ("passkey", client-side
// discoverable credential) login ceremony: the browser is given no
// allow-list and may offer any passkey it holds for this relying party, so
// the account being authenticated is not known until FinishDiscoverableLogin
// resolves it from the credential the authenticator actually used. This
// reveals nothing about which accounts exist — unlike BeginLogin, it never
// even queries CredentialStore before the browser responds.
//
// See "User verification: 'preferred' is not enforced" in the package doc:
// a discoverable login is typically single-factor, so most deployments
// offering it want protocol.VerificationRequired here, either via
// Config.UserVerification or by passing
// webauthn.WithUserVerification(protocol.VerificationRequired) in opts.
func (s *Service) BeginDiscoverableLogin(ctx context.Context, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, string, error) {
	assertion, session, err := s.wa.BeginDiscoverableLogin(s.withDefaultUV(opts)...)
	if err != nil {
		return nil, "", err
	}

	id, err := s.sessions.Put(ctx, session)
	if err != nil {
		return nil, "", err
	}
	return assertion, id, nil
}

// FinishDiscoverableLogin completes a discoverable login ceremony started by
// BeginDiscoverableLogin. It resolves the account from the credential ID the
// authenticator's response names — looked up via CredentialStore.FindByID,
// never trusted from the client beyond that lookup — and go-webauthn itself
// cross-checks the resolved identity's handle against the user handle the
// assertion separately reports, failing the ceremony on a mismatch rather
// than resolving to the wrong account.
//
// sessionID is single-use regardless of outcome, exactly like FinishLogin.
func (s *Service) FinishDiscoverableLogin(ctx context.Context, sessionID string, r *http.Request) (*LoginResult, error) {
	session, ok := s.sessions.Take(ctx, sessionID)
	if !ok {
		return nil, ErrSessionNotFound
	}

	var resolvedHandle []byte
	handler := func(rawID, _ []byte) (webauthn.User, error) {
		stored, err := s.creds.FindByID(ctx, rawID)
		if err != nil {
			return nil, err
		}
		resolvedHandle = stored.UserHandle
		return &identity{handle: stored.UserHandle, creds: []webauthn.Credential{stored.Credential}}, nil
	}

	cred, err := s.wa.FinishDiscoverableLogin(handler, *session, r)
	if err != nil {
		return nil, err
	}

	if err := s.creds.UpdateSignCount(ctx, cred.ID, *cred, s.now()); err != nil {
		return nil, fmt.Errorf("passkey: persisting sign count: %w", err)
	}
	return &LoginResult{UserHandle: resolvedHandle, Credential: *cred}, nil
}
