// Package saml is the SAML 2.0 Service Provider orchestration layer sitting
// on top of github.com/crewjam/saml. It builds AuthnRequest URLs, publishes
// SP metadata, and validates an IdP's Response into a platform-neutral
// Assertion — and it closes the gaps crewjam/saml leaves open by design:
//
//   - Assertion replay. crewjam validates NotBefore/NotOnOrAfter and the
//     signature but keeps no record of which assertion IDs it has already
//     accepted, so a captured SAMLResponse can be replayed for the rest of
//     its ~5-minute validity window. Provider.ValidateResponse rejects a
//     second presentation of the same assertion ID via a ReplayCache.
//   - Multiple assertions. crewjam parses every Assertion/EncryptedAssertion
//     element in a Response and returns the first one that validates,
//     rather than requiring exactly one. A Response smuggling a second,
//     differently-trusted assertion alongside a legitimate one is refused
//     outright before crewjam ever sees it (see ErrTooManyAssertions).
//   - Decompression bombs. Any code path in this package that inflates a
//     DEFLATE-compressed, redirect-bound SAML message (see InflateLimited)
//     enforces a hard byte cap instead of trusting the compressed stream.
//   - An absent Destination. crewjam only requires the Destination
//     attribute when the Response itself is signed or the attribute is
//     present; omitting it on an otherwise-validly-signed-Assertion
//     Response skips the check entirely. RequireDestination (on by
//     default) closes that.
//
// # Scope
//
// This package has no notion of a user, account, tenant, organization, or
// role. A validated Assertion carries a NameID, a session index, validity
// timestamps, and the raw attribute bag the IdP sent — nothing is resolved
// into an application identity. Deciding which attribute means "email",
// whether a given NameID format is acceptable, and how a NameID or
// attribute maps to an account are all policy decisions left entirely to
// the caller; three real deployments disagree about every one of them
// (see the package tests and the migration notes in the project history
// for specifics), and baking any one answer in here would make this
// package unusable by the other two.
//
// # Storage
//
// The only state this package needs to keep is the replay cache, and that
// is an interface (ReplayCache). NewMemoryReplayCache provides a bounded,
// TTL-evicting in-memory implementation that is enough on its own for a
// single process; a caller that needs replay protection to survive a
// restart or to be shared across instances supplies their own
// ReplayCache backed by whatever store they already have (SQL, Redis,
// ...) — this package does not prescribe a schema.
//
// # No logging
//
// This package never writes to a logger. Every rejection is a distinguishable
// sentinel error (see errors.go) with enough context attached (via %w and
// exported fields) for the caller to log it however their own project does.
package saml

import (
	"crypto"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"net/url"
	"time"

	crewjamsaml "github.com/crewjam/saml"
)

// Default tuning values, used when the corresponding Config field is left
// at its zero value. They are conservative enough for a normal deployment
// (a handful of IdPs, assertions on the order of a few KB) while still
// bounding worst-case memory use against a hostile or misconfigured IdP.
const (
	// DefaultMaxResponseBytes caps the decoded (POST-binding) or inflated
	// (redirect-binding) SAML Response XML this package will parse.
	// Real-world responses, even with a dozen attributes and a full
	// certificate chain in the signature, are well under 100KB.
	DefaultMaxResponseBytes = 1 << 20 // 1 MiB

	// DefaultMaxInflatedBytes caps the OUTPUT of DEFLATE decompression
	// for a redirect-bound message, independent of DefaultMaxResponseBytes
	// (which applies to the XML after decompression too). It exists
	// specifically to defend against a decompression bomb: a tiny
	// compressed payload that expands to gigabytes.
	DefaultMaxInflatedBytes = 1 << 20 // 1 MiB

	// DefaultReplayCacheCapacity bounds the in-memory replay cache's
	// entry count so a flood of distinct assertion IDs cannot grow it
	// without limit.
	DefaultReplayCacheCapacity = 65536

	// DefaultReplayExpiryMargin is added on top of an assertion's
	// NotOnOrAfter (plus crewjam's own MaxClockSkew) when computing how
	// long its ID must be remembered. The margin exists so that even a
	// process with a somewhat-behind clock, or a caller that validates
	// slightly late, still closes the full window crewjam would accept
	// a replay in.
	DefaultReplayExpiryMargin = time.Minute
)

// Config configures a Provider. EntityID, ACSURL and IDPMetadata are
// required; everything else has a documented default.
type Config struct {
	// EntityID is this SP's own entity ID, published in SP metadata and
	// checked against every assertion's AudienceRestriction.
	EntityID string

	// ACSURL is the URL this SP receives SAMLResponse POSTs at. It is
	// published in SP metadata as the (only) AssertionConsumerService,
	// and every Response's Destination must equal it exactly (see
	// RequireDestination).
	ACSURL string

	// Key signs outgoing AuthnRequests and LogoutRequests, and decrypts
	// an EncryptedAssertion when AllowEncryptedAssertions is true. Not
	// required for an SP that never signs requests and never accepts
	// encrypted assertions, but Certificate must be set if Key is.
	Key crypto.Signer

	// Certificate is the SP's own certificate, matching Key. Published
	// in SP metadata as both the signing and encryption KeyDescriptor.
	Certificate *x509.Certificate

	// IDPMetadata is the parsed metadata of the IdP this Provider trusts.
	// Fetching it, verifying its provenance, and refreshing it on a
	// schedule (IdPs rotate signing certs) are all the caller's job —
	// this package only consumes the parsed result. Required.
	IDPMetadata *crewjamsaml.EntityDescriptor

	// AllowIDPInitiated accepts a Response with no matching AuthnRequest
	// (no InResponseTo to check against). Off by default: an
	// IdP-initiated flow carries no request-bound state, which is itself
	// a CSRF-adjacent surface, so a caller opts in deliberately.
	AllowIDPInitiated bool

	// NameIDFormat is placed in the AuthnRequest's NameIDPolicy. Left at
	// "", crewjam defaults to "transient" — which forces a fresh,
	// unlinkable NameID on every login and is very often not what an
	// admin configured on the IdP side (this bit every one of the three
	// projects this package was assembled from). UnspecifiedNameIDFormat
	// emits no Format at all, letting the IdP fall back to whatever its
	// admin configured, and is used when this field is "".
	NameIDFormat crewjamsaml.NameIDFormat

	// ReplayCache records consumed assertion IDs. If nil, a
	// NewMemoryReplayCache with DefaultReplayCacheCapacity is used.
	ReplayCache ReplayCache

	// ReplayExpiryMargin is added on top of an assertion's effective
	// expiry (NotOnOrAfter, or the latest SubjectConfirmationData
	// NotOnOrAfter if later, plus crewjam's MaxClockSkew) when deciding
	// how long the replay cache must remember its ID. Zero uses
	// DefaultReplayExpiryMargin.
	ReplayExpiryMargin time.Duration

	// MaxResponseBytes caps the size of the decoded Response XML this
	// Provider will parse, independent of whatever limit the caller's
	// HTTP server places on the request body. Zero uses
	// DefaultMaxResponseBytes.
	MaxResponseBytes int64

	// MaxInflatedBytes caps DEFLATE decompression output when validating
	// a redirect-bound (compressed) message. Zero uses
	// DefaultMaxInflatedBytes.
	MaxInflatedBytes int64

	// RequireDestination rejects a Response whose Destination attribute
	// is absent, in addition to crewjam's own check (which always
	// rejects a Destination that is PRESENT but wrong). Defaults to true
	// (via requireDestinationDefault) — set explicitly to false only for
	// an IdP verified to omit Destination on every response.
	RequireDestination *bool

	// RejectWeakSignatures refuses a Response that declares a
	// SignatureMethod or DigestMethod weaker than SHA-256 anywhere in the
	// document (the outer Response signature, the Assertion signature,
	// or any Reference digest) — most importantly rsa-sha1, which ADFS
	// and older Keycloak default to and which no longer offers a
	// meaningful collision resistance. Checked on the raw XML, before
	// any signature is verified, so a strong outer signature can never
	// vouch for a weak inner one. Defaults to true.
	RejectWeakSignatures *bool

	// AllowEncryptedAssertions permits a Response containing an
	// EncryptedAssertion (decrypted with Key). Off by default: none of
	// the deployments this package was built from use it, decryption is
	// a padding-oracle-shaped attack surface, and TLS already covers the
	// transport for the Web SSO profile.
	AllowEncryptedAssertions bool

	// StrictAttributes rejects an assertion in which the same attribute
	// Name (or FriendlyName) is declared by more than one distinct
	// <Attribute> element — as opposed to one <Attribute> element with
	// several <AttributeValue> children, which is the normal way to send
	// a multi-valued attribute and is always allowed. Off by default,
	// since it is a stricter-than-spec policy some callers rely on (to
	// stop attribute pollution feeding a role-mapping rule) and others
	// have never needed.
	StrictAttributes bool

	// Clock returns the current time. Nil uses time.Now. Tests override
	// it to exercise expiry without sleeping.
	Clock func() time.Time
}

func (c Config) now() time.Time {
	if c.Clock != nil {
		return c.Clock()
	}
	return time.Now()
}

func (c Config) maxResponseBytes() int64 {
	if c.MaxResponseBytes > 0 {
		return c.MaxResponseBytes
	}
	return DefaultMaxResponseBytes
}

func (c Config) maxInflatedBytes() int64 {
	if c.MaxInflatedBytes > 0 {
		return c.MaxInflatedBytes
	}
	return DefaultMaxInflatedBytes
}

func (c Config) replayExpiryMargin() time.Duration {
	if c.ReplayExpiryMargin > 0 {
		return c.ReplayExpiryMargin
	}
	return DefaultReplayExpiryMargin
}

func (c Config) requireDestination() bool {
	if c.RequireDestination != nil {
		return *c.RequireDestination
	}
	return true
}

func (c Config) rejectWeakSignatures() bool {
	if c.RejectWeakSignatures != nil {
		return *c.RejectWeakSignatures
	}
	return true
}

// Bool is a small helper for the *bool Config fields, so a caller can write
// Config{RequireDestination: saml.Bool(false)} instead of taking the
// address of a local variable.
func Bool(b bool) *bool { return &b }

// Provider is a validated SAML SP orchestration handle: an AuthnRequest
// builder, a metadata publisher, and a Response validator, all built around
// a single crewjam/saml ServiceProvider. Nothing on a Provider is mutated
// after New returns, so it is safe for concurrent use as long as its
// ReplayCache is (Config.ReplayCache documents that requirement; the
// built-in MemoryReplayCache meets it).
type Provider struct {
	cfg   Config
	sp    *crewjamsaml.ServiceProvider
	cache ReplayCache
}

// New builds a Provider from cfg. It fails if EntityID, ACSURL, or
// IDPMetadata are missing, or if ACSURL does not parse as a URL.
func New(cfg Config) (*Provider, error) {
	if cfg.EntityID == "" {
		return nil, fmt.Errorf("saml: Config.EntityID is required")
	}
	if cfg.ACSURL == "" {
		return nil, fmt.Errorf("saml: Config.ACSURL is required")
	}
	if cfg.IDPMetadata == nil {
		return nil, fmt.Errorf("saml: Config.IDPMetadata is required")
	}
	acsURL, err := url.Parse(cfg.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("saml: parse Config.ACSURL: %w", err)
	}
	if (cfg.Key == nil) != (cfg.Certificate == nil) {
		return nil, fmt.Errorf("saml: Config.Key and Config.Certificate must be set together")
	}

	nameIDFormat := cfg.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = crewjamsaml.UnspecifiedNameIDFormat
	}

	sp := &crewjamsaml.ServiceProvider{
		EntityID:          cfg.EntityID,
		AcsURL:            *acsURL,
		Key:               cfg.Key,
		Certificate:       cfg.Certificate,
		IDPMetadata:       cfg.IDPMetadata,
		AllowIDPInitiated: cfg.AllowIDPInitiated,
		AuthnNameIDFormat: nameIDFormat,
	}

	cache := cfg.ReplayCache
	if cache == nil {
		cache = NewMemoryReplayCache(DefaultReplayCacheCapacity)
	}

	return &Provider{cfg: cfg, sp: sp, cache: cache}, nil
}

// EntityID returns the SP entity ID this Provider was configured with.
func (p *Provider) EntityID() string { return p.cfg.EntityID }

// ACSURL returns the ACS URL this Provider was configured with.
func (p *Provider) ACSURL() string { return p.cfg.ACSURL }

// Metadata returns the SP metadata document describing this Provider, for
// the caller to serve (e.g. XML-marshal it) at whatever URL the IdP admin
// expects to import it from.
func (p *Provider) Metadata() *crewjamsaml.EntityDescriptor {
	return p.sp.Metadata()
}

// MetadataXML returns Metadata marshaled as indented XML, ready to serve
// at whatever URL the IdP admin expects to import it from.
func (p *Provider) MetadataXML() ([]byte, error) {
	return xml.MarshalIndent(p.Metadata(), "", "  ")
}

// AuthnRequest is the result of building an SP-initiated login redirect.
type AuthnRequest struct {
	// ID is the AuthnRequest's ID. The caller must persist it (however
	// they see fit — a server-side store, or embedded in RelayState —
	// this package does not care which) and pass it back as one of
	// possibleRequestIDs to ValidateResponse, so the eventual Response's
	// InResponseTo can be checked. Not needed if AllowIDPInitiated is
	// the only flow in use.
	ID string

	// RedirectURL is where to send the browser to start the login at the
	// IdP (HTTP-Redirect binding).
	RedirectURL string
}

// NewAuthnRequest builds an SP-initiated AuthnRequest and the URL to
// redirect the browser to, using the HTTP-Redirect binding to the IdP and
// requesting the HTTP-POST binding for the response. relayState is placed
// on the redirect verbatim (RFC 6.4) and handed back by the IdP with the
// Response; a common pattern is to fold the AuthnRequest ID and a
// post-login return path into it, but this package does not require any
// particular shape.
func (p *Provider) NewAuthnRequest(relayState string) (*AuthnRequest, error) {
	if p == nil || p.sp == nil || p.sp.IDPMetadata == nil {
		return nil, ErrNotConfigured
	}
	idpURL := p.sp.GetSSOBindingLocation(crewjamsaml.HTTPRedirectBinding)
	if idpURL == "" {
		return nil, fmt.Errorf("saml: IdP metadata has no HTTP-Redirect SingleSignOnService")
	}
	req, err := p.sp.MakeAuthenticationRequest(idpURL, crewjamsaml.HTTPRedirectBinding, crewjamsaml.HTTPPostBinding)
	if err != nil {
		return nil, fmt.Errorf("saml: make authentication request: %w", err)
	}
	redirectURL, err := req.Redirect(relayState, p.sp)
	if err != nil {
		return nil, fmt.Errorf("saml: build redirect URL: %w", err)
	}
	return &AuthnRequest{ID: req.ID, RedirectURL: redirectURL.String()}, nil
}
