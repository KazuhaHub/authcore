package passkey

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// ErrCredentialNotFound is returned by a CredentialStore's FindByID when no
// credential is stored under the given id. Implementations backed by a real
// database should return this exact sentinel (directly, or wrapped so
// errors.Is matches) so this package's discoverable-login lookup behaves
// consistently across backends.
var ErrCredentialNotFound = errors.New("passkey: credential not found")

// StoredCredential is a WebAuthn credential together with the opaque handle
// of the account it belongs to. UserHandle is exactly the byte string a
// caller passed as handle to BeginRegistration — this package never
// inspects or interprets it, only threads it through.
type StoredCredential struct {
	UserHandle []byte
	Credential webauthn.Credential
}

// CredentialStore is the minimal, caller-implemented contract this package
// needs to persist and look up WebAuthn credentials. It says nothing about
// who a credential belongs to beyond the opaque UserHandle on
// StoredCredential — no user, account, or tenant concept, and no assumption
// about the backing storage engine. A real implementation is typically a
// thin wrapper over one SQL table; see the "Storage" section of
// pkg.go.dev/github.com/go-webauthn/webauthn/webauthn for the column shape
// go-webauthn itself recommends, which this interface's methods map onto
// directly.
//
// This is deliberately NOT a full credential-management API: renaming a
// credential for display, listing them for a "your devices" page, deleting
// one, or counting how many accounts have one are account-model operations
// with no WebAuthn-ceremony content. They belong in the caller's own
// repository code, built directly on their own storage, using the
// credential and user-handle values this package already round-trips to
// them — not in this interface.
type CredentialStore interface {
	// FindByID returns the credential stored under the raw credential ID (as
	// in webauthn.Credential.ID, or a response's RawID), or
	// ErrCredentialNotFound if none exists. Used to resolve identity during
	// a discoverable (usernameless) login.
	FindByID(ctx context.Context, credentialID []byte) (StoredCredential, error)

	// FindByUserHandle returns every credential registered under handle, in
	// any order. A handle with none returns an empty (or nil) slice and a
	// nil error — "no credentials yet" is not an error condition. Used to
	// build registration exclusion lists and login allow-lists, and to load
	// the current authenticator state (SignCount, Flags) an allow-listed
	// login must be verified against.
	FindByUserHandle(ctx context.Context, handle []byte) ([]StoredCredential, error)

	// Save persists a newly registered credential. Implementations should
	// reject (or upsert, if that is the caller's chosen policy) a duplicate
	// Credential.ID; BeginRegistration already excludes a handle's existing
	// credentials via go-webauthn's WithExclusions, so a collision here
	// signals either a client that ignored that exclusion list or an actual
	// ID collision.
	Save(ctx context.Context, cred StoredCredential) error

	// UpdateSignCount persists a credential's advanced authenticator state
	// after a successful login. cred is the full post-ceremony credential —
	// go-webauthn's own storage guidance is that SignCount, CloneWarning,
	// and the UserVerified/BackupState flags must all be written back on
	// every successful login, not just the counter, so an implementation
	// that only has a sign_count column should extract what it needs from
	// cred rather than persist it verbatim. usedAt is the ceremony's finish
	// time, for a last-used timestamp.
	//
	// # The write-back contract
	//
	// Both FinishLogin and FinishDiscoverableLogin call this once after the
	// assertion verifies, INCLUDING when cred.Authenticator.CloneWarning is
	// set — this package does not treat a counter rollback as a verification
	// failure. Being called is not the same as being obliged to write: an
	// implementation may apply its own policy and REFUSE BEFORE WRITING,
	// returning a classifiable error. What it must not do is return nil
	// while claiming a write it did not perform.
	//
	// A non-nil error fails the ceremony: both Finish methods return a nil
	// *LoginResult and that error, wrapped so errors.Is / errors.As still
	// reach it. This package never logs a write-back error and carries on —
	// an application that rejects a credential on a clone warning needs the
	// rejection to BE the outcome of the login, not a note attached to a
	// successful one. The ceremony's challenge is already consumed by then,
	// so a refused login has to be begun again.
	//
	// Refusing before writing is also the only way to get the stronger
	// property. This package does not attempt to undo a write an
	// implementation has already made: a Store that persists first and
	// decides afterwards has already changed the record.
	UpdateSignCount(ctx context.Context, credentialID []byte, cred webauthn.Credential, usedAt time.Time) error
}

// MemoryCredentialStore is a process-local CredentialStore backed by a plain
// map, safe for concurrent use. It has no eviction and no TTL: unlike the
// ephemeral ceremony state MemoryStore holds, a WebAuthn credential is
// permanent account data that must survive for the credential's lifetime —
// a store that aged entries out would silently lock people out of their
// passkeys. It exists for tests and local prototyping; every real
// deployment should implement CredentialStore against its own database
// instead (see the CredentialStore doc for the recommended shape).
type MemoryCredentialStore struct {
	mu   sync.RWMutex
	byID map[string]StoredCredential
}

// NewMemoryCredentialStore returns an empty MemoryCredentialStore.
func NewMemoryCredentialStore() *MemoryCredentialStore {
	return &MemoryCredentialStore{byID: make(map[string]StoredCredential)}
}

// FindByID implements CredentialStore.
func (m *MemoryCredentialStore) FindByID(_ context.Context, credentialID []byte) (StoredCredential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sc, ok := m.byID[string(credentialID)]
	if !ok {
		return StoredCredential{}, ErrCredentialNotFound
	}
	return sc, nil
}

// FindByUserHandle implements CredentialStore.
func (m *MemoryCredentialStore) FindByUserHandle(_ context.Context, handle []byte) ([]StoredCredential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []StoredCredential
	for _, sc := range m.byID {
		if string(sc.UserHandle) == string(handle) {
			out = append(out, sc)
		}
	}
	return out, nil
}

// Save implements CredentialStore. It errors if credentialID is already
// stored.
func (m *MemoryCredentialStore) Save(_ context.Context, cred StoredCredential) error {
	key := string(cred.Credential.ID)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.byID[key]; exists {
		return errors.New("passkey: credential already registered")
	}
	m.byID[key] = cred
	return nil
}

// UpdateSignCount implements CredentialStore. It errors if credentialID is
// not stored.
func (m *MemoryCredentialStore) UpdateSignCount(_ context.Context, credentialID []byte, cred webauthn.Credential, _ time.Time) error {
	key := string(credentialID)
	m.mu.Lock()
	defer m.mu.Unlock()
	sc, ok := m.byID[key]
	if !ok {
		return ErrCredentialNotFound
	}
	sc.Credential = cred
	m.byID[key] = sc
	return nil
}
