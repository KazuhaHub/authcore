package passkey

import "github.com/go-webauthn/webauthn/webauthn"

// identity adapts a caller-supplied handle plus a set of already-loaded
// credentials to go-webauthn's webauthn.User interface. It is this package's
// only notion of "who": handle is opaque (see BeginRegistration), and
// name/displayName exist purely as authenticator-UI labels — go-webauthn
// never uses them for anything security-relevant, and neither does this
// package.
type identity struct {
	handle      []byte
	name        string
	displayName string
	creds       []webauthn.Credential
}

func (u *identity) WebAuthnID() []byte                         { return u.handle }
func (u *identity) WebAuthnName() string                       { return u.name }
func (u *identity) WebAuthnDisplayName() string                { return u.displayName }
func (u *identity) WebAuthnCredentials() []webauthn.Credential { return u.creds }
