package passkey

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestNew_RequiresCredentials(t *testing.T) {
	_, err := New(Config{RPID: testRPID, RPDisplayName: testDisplay, RPOrigins: []string{testOrigin}})
	if err == nil {
		t.Fatal("New without Config.Credentials must fail")
	}
}

func TestNew_RequiresDisplayName(t *testing.T) {
	_, err := New(Config{RPID: testRPID, RPOrigins: []string{testOrigin}, Credentials: NewMemoryCredentialStore()})
	if err == nil {
		t.Fatal("New without Config.RPDisplayName must fail")
	}
}

func TestNew_RejectsInvalidRPConfig(t *testing.T) {
	// No RPOrigins at all: go-webauthn itself must reject this.
	_, err := New(Config{RPID: testRPID, RPDisplayName: testDisplay, Credentials: NewMemoryCredentialStore()})
	if err == nil {
		t.Fatal("New with no RPOrigins must fail")
	}
}

// TestNew_AttestationDefaultsToNone proves the documented default -- no
// attestation is requested unless the caller opts in.
func TestNew_AttestationDefaultsToNone(t *testing.T) {
	svc, _ := newTestService(t, nil)
	if got := svc.wa.Config.AttestationPreference; got != protocol.PreferNoAttestation {
		t.Fatalf("default AttestationPreference = %q, want %q", got, protocol.PreferNoAttestation)
	}
}

// TestNew_AttestationPreferenceConfigurable proves indirect/direct can be
// turned on.
func TestNew_AttestationPreferenceConfigurable(t *testing.T) {
	for _, pref := range []protocol.ConveyancePreference{protocol.PreferIndirectAttestation, protocol.PreferDirectAttestation} {
		svc, _ := newTestService(t, func(cfg *Config) { cfg.AttestationPreference = pref })
		if got := svc.wa.Config.AttestationPreference; got != pref {
			t.Fatalf("AttestationPreference = %q, want %q", got, pref)
		}
	}
}

// TestNew_UserVerificationDefaultsToPreferred proves the package's own
// default, both for the login default and for the registration
// AuthenticatorSelection it fills in.
func TestNew_UserVerificationDefaultsToPreferred(t *testing.T) {
	svc, _ := newTestService(t, nil)
	if svc.defaultLoginUV != protocol.VerificationPreferred {
		t.Fatalf("default login UserVerification = %q, want %q", svc.defaultLoginUV, protocol.VerificationPreferred)
	}
	if got := svc.wa.Config.AuthenticatorSelection.UserVerification; got != protocol.VerificationPreferred {
		t.Fatalf("default AuthenticatorSelection.UserVerification = %q, want %q", got, protocol.VerificationPreferred)
	}
}

func TestNew_UserVerificationConfigurable(t *testing.T) {
	svc, _ := newTestService(t, func(cfg *Config) { cfg.UserVerification = protocol.VerificationRequired })
	if svc.defaultLoginUV != protocol.VerificationRequired {
		t.Fatalf("login UserVerification = %q, want %q", svc.defaultLoginUV, protocol.VerificationRequired)
	}
	if got := svc.wa.Config.AuthenticatorSelection.UserVerification; got != protocol.VerificationRequired {
		t.Fatalf("AuthenticatorSelection.UserVerification = %q, want %q", got, protocol.VerificationRequired)
	}
}

// TestNew_ExplicitAuthenticatorSelectionUVNotOverridden proves an explicit
// AuthenticatorSelection.UserVerification set by the caller is not clobbered
// by the Config.UserVerification default-filling.
func TestNew_ExplicitAuthenticatorSelectionUVNotOverridden(t *testing.T) {
	svc, _ := newTestService(t, func(cfg *Config) {
		cfg.UserVerification = protocol.VerificationRequired
		cfg.AuthenticatorSelection.UserVerification = protocol.VerificationDiscouraged
	})
	if got := svc.wa.Config.AuthenticatorSelection.UserVerification; got != protocol.VerificationDiscouraged {
		t.Fatalf("explicit AuthenticatorSelection.UserVerification = %q, want it left as Discouraged", got)
	}
	// The login default is unaffected by that registration-only override.
	if svc.defaultLoginUV != protocol.VerificationRequired {
		t.Fatalf("login UserVerification = %q, want %q", svc.defaultLoginUV, protocol.VerificationRequired)
	}
}

func TestNew_SessionsDefaultsToMemoryStore(t *testing.T) {
	svc, _ := newTestService(t, nil)
	if _, ok := svc.sessions.(*MemoryStore); !ok {
		t.Fatalf("default Sessions = %T, want *MemoryStore", svc.sessions)
	}
}
