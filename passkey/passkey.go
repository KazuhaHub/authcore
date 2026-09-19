// Package passkey orchestrates the full lifecycle of a WebAuthn ("passkey")
// ceremony on top of github.com/go-webauthn/webauthn: registration
// (enrollment) and authentication, each as a begin/finish pair, plus
// client-side discoverable ("usernameless") login. go-webauthn documents two
// things it deliberately leaves to the caller: where the per-ceremony
// challenge lives between Begin and Finish, and where credential records are
// persisted. This package fills both in — behind the SessionStore and
// CredentialStore interfaces, with a bounded in-memory SessionStore usable
// out of the box — and adds the orchestration a real deployment needs around
// them: automatic exclusion/allow lists, a configurable default user
// verification requirement (and a documented explanation of what "preferred"
// does and does not enforce), and counter-rollback (clone) detection surfaced
// to the caller rather than decided for them.
//
// # Mechanism, not policy
//
// Like every package in this module, passkey knows nothing about accounts,
// users, tenants, organizations, or roles — that vocabulary does not appear
// anywhere in its public API and never will. Where the package needs to tell
// one identity apart from another, it accepts an opaque byte-string "user
// handle" (exactly the WebAuthn user handle passed to a caller's
// authenticator) and never interprets it. A caller that wants to scope
// credentials to an account looks the account up on their own, derives a
// stable handle for it however they see fit, and passes that handle in; this
// package only ever round-trips it.
//
// Credential *management* that has no WebAuthn-ceremony content — listing
// credentials for a "your devices" page, letting a user rename or delete one,
// counting how many accounts have a passkey — is deliberately not part of
// this package's API. Those are thin queries against whatever storage
// CredentialStore is backed by, and belong in the caller's own repository
// code, keyed by the credential and user-handle values this package already
// hands back.
//
// The package also does not log anything. Every ceremony outcome this
// package cannot fully resolve on its own — a clone/rollback signal, a
// discoverable login's resolved identity, a session lookup miss — is placed
// in a return value, and it is entirely the caller's decision how (or
// whether) to record it.
//
// # Registration and login
//
// BeginRegistration / FinishRegistration enroll a new credential for an
// already-identified handle (e.g. from a logged-in account adding a second
// device). BeginLogin / FinishLogin verify a credential against a single,
// already-identified handle (e.g. a passkey used as a second factor after a
// password). BeginDiscoverableLogin / FinishDiscoverableLogin run the
// usernameless "passkey proper" ceremony, where the identity is not known
// until the authenticator's own response names a credential; the account is
// resolved via CredentialStore.FindByID, never trusted from the client
// verbatim — go-webauthn cross-checks it against the user handle the
// assertion itself reports and fails the ceremony on a mismatch.
//
// # Clone / counter-rollback detection
//
// Every authenticator that implements a signature counter is expected to
// report a strictly increasing value on each use; go-webauthn compares the
// reported counter against the value on file and sets
// Credential.Authenticator.CloneWarning when it did not advance — a sign the
// credential's private key may exist in more than one place. An
// authenticator that never implements a counter legitimately reports 0 every
// time, and that alone is never flagged (go-webauthn exempts the all-zero
// case).
//
// This package surfaces CloneWarning on the LoginResult it returns and does
// not act on it. What it being set should MEAN for that login — refuse it
// outright, accept it but raise an alert, or something else — is a decision
// this package leaves entirely to the caller, and there are exactly two
// places to make it:
//
//   - Inside CredentialStore.UpdateSignCount, which always runs before
//     FinishLogin / FinishDiscoverableLogin returns. Refusing there returns
//     a nil *LoginResult and the Store's error, so the login fails — and
//     because the refusal happens before the write, the stored record is
//     untouched. This is the way to reject a flagged login.
//   - On the returned LoginResult, after the fact. The login can still be
//     rejected, but the advanced counter and flags have already been
//     written back; go-webauthn's storage guidance is that they must be,
//     on every cryptographically successful login.
//
// # User verification: "preferred" is not enforced
//
// go-webauthn only checks user verification (PIN/biometric, as opposed to
// mere possession) server-side when a ceremony's requirement is
// protocol.VerificationRequired. protocol.VerificationPreferred — the
// package's own default, see Config.UserVerification — is conveyed to the
// authenticator as a hint but never checked against the response. A
// discoverable ("usernameless") login is single-factor: there is no password
// behind it, so a deployment that offers BeginDiscoverableLogin as a real
// sign-in method (not merely a second factor) should set UserVerification to
// protocol.VerificationRequired for that ceremony, either via Config or by
// passing webauthn.WithUserVerification(protocol.VerificationRequired) to
// BeginDiscoverableLogin directly.
package passkey

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Sentinel errors returned by this package. Errors originating from
// go-webauthn itself (a failed signature, origin, or RP ID check; a session
// state validation) are returned unwrapped from the Begin/Finish calls that
// produced them — this package does not re-wrap them behind its own type, so
// a caller that wants to inspect one uses go-webauthn's protocol.Error
// directly.
var (
	// ErrSessionNotFound is returned by a Finish call when sessionID is
	// unknown, already consumed, or expired. These three cases are
	// indistinguishable by design: a Finish call cannot be used to probe
	// which session ids were ever issued or how long ago. The ceremony must
	// be restarted from Begin.
	ErrSessionNotFound = errors.New("passkey: ceremony session not found or expired")

	// ErrNoCredentials is returned by BeginLogin when handle has no
	// credentials enrolled to build an allow-list from. It is never returned
	// by BeginDiscoverableLogin, which does not know the identity yet.
	ErrNoCredentials = errors.New("passkey: no credentials enrolled for this handle")
)

// Config configures a Service.
type Config struct {
	// RPID is the WebAuthn Relying Party ID: the effective domain the
	// credentials are scoped to (e.g. "example.com"), never a full origin
	// (no scheme, no port). Required. Deriving this from an
	// attacker-influenced value such as an HTTP request's Host header is the
	// classic RP-ID-poisoning mistake — it must come from configuration the
	// caller controls.
	RPID string

	// RPDisplayName is a human-readable name for the relying party that some
	// authenticator UIs show during a ceremony. Required: WebAuthn itself
	// permits an empty string here, but this package does not, since a blank
	// prompt is never the deployment's intent.
	RPDisplayName string

	// RPOrigins lists every origin a ceremony may be started from and
	// finished against (e.g. "https://example.com",
	// "https://accounts.example.com"). A response is accepted if its origin
	// matches any entry — this is how one relying party serves several
	// domains or subdomains. At least one is required.
	RPOrigins []string

	// AuthenticatorSelection is the default sent with every registration
	// ceremony. Its zero value is go-webauthn's own default: ResidentKey
	// unset behaves as "discouraged", so a deployment that wants credentials
	// to actually be client-side discoverable (the "passkey" in
	// BeginDiscoverableLogin) should set
	// ResidentKey: protocol.ResidentKeyRequirementPreferred (or ...Required).
	// AuthenticatorSelection.UserVerification, if left as the empty string,
	// is filled in from Config.UserVerification. Override per call with
	// webauthn.WithAuthenticatorSelection.
	AuthenticatorSelection protocol.AuthenticatorSelection

	// AttestationPreference is the default attestation conveyance preference
	// sent with every registration ceremony. The zero value defaults to
	// protocol.PreferNoAttestation ("none"): no attestation statement is
	// requested, which reveals nothing about the authenticator model and is
	// the right default for almost every deployment. Set
	// protocol.PreferIndirectAttestation or protocol.PreferDirectAttestation
	// to request one instead. Override per call with
	// webauthn.WithConveyancePreference.
	AttestationPreference protocol.ConveyancePreference

	// UserVerification is this package's default user-verification
	// requirement. It is applied to every login ceremony (BeginLogin and
	// BeginDiscoverableLogin alike) unless a call overrides it by passing its
	// own webauthn.WithUserVerification, and it fills in
	// AuthenticatorSelection.UserVerification for registration when that is
	// left as the empty string. See "User verification: 'preferred' is not
	// enforced" in the package doc for why the choice between Preferred and
	// Required matters more than it looks. The zero value defaults to
	// protocol.VerificationPreferred.
	UserVerification protocol.UserVerificationRequirement

	// Sessions holds the challenge state a ceremony's Begin call produces
	// until its Finish call consumes it. Defaults to DefaultMemoryStore()
	// when nil.
	Sessions SessionStore

	// Credentials is this package's only persistent dependency. Required —
	// there is no in-memory default, because a WebAuthn credential is
	// permanent account data (see CredentialStore and MemoryCredentialStore).
	Credentials CredentialStore

	// Now stands in for time.Now in tests. Defaults to time.Now.
	Now func() time.Time
}

// Service orchestrates WebAuthn ceremonies for one relying-party
// configuration. It is safe for concurrent use; a typical deployment
// constructs one Service at startup and shares it across every request
// goroutine.
type Service struct {
	wa       *webauthn.WebAuthn
	sessions SessionStore
	creds    CredentialStore
	now      func() time.Time

	defaultLoginUV protocol.UserVerificationRequirement
}

// New builds a Service from cfg. It errors on an incomplete or invalid
// relying-party configuration (RPID / RPDisplayName / RPOrigins — see
// go-webauthn's own webauthn.New for what it validates) or a missing
// Credentials store.
func New(cfg Config) (*Service, error) {
	if cfg.Credentials == nil {
		return nil, errors.New("passkey: Config.Credentials is required")
	}
	if cfg.RPDisplayName == "" {
		return nil, errors.New("passkey: Config.RPDisplayName is required")
	}

	uv := cfg.UserVerification
	if uv == "" {
		uv = protocol.VerificationPreferred
	}

	authSel := cfg.AuthenticatorSelection
	if authSel.UserVerification == "" {
		authSel.UserVerification = uv
	}

	attestation := cfg.AttestationPreference
	if attestation == "" {
		attestation = protocol.PreferNoAttestation
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPID:                   cfg.RPID,
		RPDisplayName:          cfg.RPDisplayName,
		RPOrigins:              cfg.RPOrigins,
		AuthenticatorSelection: authSel,
		AttestationPreference:  attestation,
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: %w", err)
	}

	sessions := cfg.Sessions
	if sessions == nil {
		sessions = DefaultMemoryStore()
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	return &Service{
		wa:             wa,
		sessions:       sessions,
		creds:          cfg.Credentials,
		now:            now,
		defaultLoginUV: uv,
	}, nil
}

// withDefaultUV prepends the service's default user-verification requirement
// to opts, so an explicit option in opts (applied after, and so evaluated
// last by go-webauthn's functional-option handling) overrides it.
func (s *Service) withDefaultUV(opts []webauthn.LoginOption) []webauthn.LoginOption {
	full := make([]webauthn.LoginOption, 0, len(opts)+1)
	full = append(full, webauthn.WithUserVerification(s.defaultLoginUV))
	full = append(full, opts...)
	return full
}

// descriptorsOf converts stored credentials to the descriptor list
// go-webauthn's exclusion/allow-list options take.
func descriptorsOf(stored []StoredCredential) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(stored))
	for _, sc := range stored {
		out = append(out, sc.Credential.Descriptor())
	}
	return out
}

// credentialsOf extracts the webauthn.Credential values from stored
// credentials, in the shape webauthn.User.WebAuthnCredentials expects.
func credentialsOf(stored []StoredCredential) []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(stored))
	for _, sc := range stored {
		out = append(out, sc.Credential)
	}
	return out
}
