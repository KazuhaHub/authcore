package saml

import (
	"strings"
	"time"

	crewjamsaml "github.com/crewjam/saml"
)

// Assertion is a platform-neutral view of a validated SAML assertion. It
// carries exactly what the SAML wire format carries — nothing is resolved
// into an account, a role, or any other application concept. A caller maps
// NameID and Attributes onto their own identity model using whatever
// configuration (which attribute is "email", which NameID formats are
// acceptable, ...) that model requires.
type Assertion struct {
	// ID is the assertion's ID, guaranteed non-empty by the time this
	// struct exists (ValidateResponse/ValidateResponseXML reject an
	// assertion with an empty ID before it reaches here — see
	// ErrMissingAssertionID). It is what the replay cache keys on.
	ID string

	// IssueInstant is when the IdP says it created the assertion.
	IssueInstant time.Time

	// Issuer is the IdP's entity ID, as declared in the assertion.
	Issuer string

	// NameID is the value of <Subject><NameID>. Its meaning (a stable
	// account key, a human-readable UPN, an opaque per-SP pairwise
	// identifier, ...) depends entirely on how the IdP admin configured
	// the NameID source, which is why NameIDFormat is exposed alongside
	// it: a caller that needs a stable identifier should check the
	// format (crewjamsaml.TransientNameIDFormat is a fresh value on
	// every login and cannot key anything durable) rather than assume.
	NameID string

	// NameIDFormat is the Format attribute of <Subject><NameID>, e.g.
	// "urn:oasis:names:tc:SAML:2.0:nameid-format:transient". Empty if the
	// IdP did not set one.
	NameIDFormat string

	// SessionIndex is the AuthnStatement's SessionIndex, used to
	// correlate a later Single Logout request with this session. Empty
	// if the IdP did not send an AuthnStatement or left it blank.
	SessionIndex string

	// NotBefore and NotOnOrAfter are the assertion's Conditions validity
	// window (zero if the assertion had no Conditions element, which
	// crewjam's own validation would already have rejected in that case
	// for anything but a trivially permissive IdP — they are exposed
	// here mainly for a caller that wants to log or display them).
	NotBefore    time.Time
	NotOnOrAfter time.Time

	// Attributes holds every <Attribute> value, keyed by both its Name
	// and (if different) its FriendlyName — so a caller can look a value
	// up by whichever the admin configured to type in. Multiple
	// <AttributeValue> children of one <Attribute> element are ALWAYS
	// merged into one slice (that is simply how SAML expresses a
	// multi-valued attribute); see Config.StrictAttributes for a stricter
	// policy on the SAME name appearing on more than one <Attribute>
	// element.
	Attributes map[string][]string
}

// Attribute returns the first value for the named attribute (matched
// against either the Name or FriendlyName the IdP used), or "" if it was
// not sent.
func (a *Assertion) Attribute(name string) string {
	if a == nil {
		return ""
	}
	if vs := a.Attributes[name]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// dedupeKeys returns the distinct non-empty strings among keys, preserving
// order. Used because an <Attribute>'s Name and FriendlyName are frequently
// the identical string (many IdPs send both as e.g. "groups"), which must
// index Attributes once, not collide with itself under StrictAttributes.
func dedupeKeys(keys ...string) []string {
	seen := make(map[string]bool, len(keys))
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out
}

// assertionFromCrewjam converts a validated *crewjamsaml.Assertion into our
// neutral Assertion, applying Config.StrictAttributes if set. The caller
// must have already run every other check (signature, replay, ...) — this
// function only reshapes data, it does not itself validate trust.
func assertionFromCrewjam(a *crewjamsaml.Assertion, strictAttributes bool) (*Assertion, error) {
	out := &Assertion{
		ID:           a.ID,
		IssueInstant: a.IssueInstant,
		Attributes:   map[string][]string{},
	}
	out.Issuer = a.Issuer.Value
	if a.Subject != nil && a.Subject.NameID != nil {
		out.NameID = a.Subject.NameID.Value
		out.NameIDFormat = a.Subject.NameID.Format
	}
	if a.Conditions != nil {
		out.NotBefore = a.Conditions.NotBefore
		out.NotOnOrAfter = a.Conditions.NotOnOrAfter
	}
	for _, stmt := range a.AuthnStatements {
		if stmt.SessionIndex != "" {
			out.SessionIndex = stmt.SessionIndex
			break
		}
	}

	seen := map[string]bool{}
	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			var vals []string
			for _, v := range attr.Values {
				vals = append(vals, v.Value)
			}
			keys := dedupeKeys(attr.Name, attr.FriendlyName)
			for _, key := range keys {
				if strictAttributes {
					if seen[key] {
						return nil, ErrDuplicateAttribute
					}
					seen[key] = true
				}
				out.Attributes[key] = append(out.Attributes[key], vals...)
			}
		}
	}
	return out, nil
}

// IsTransient reports whether NameIDFormat is the SAML transient format —
// a value the IdP mints fresh on every login and which therefore cannot
// serve as a durable identifier. Provided as a convenience since every
// caller that keys an identity off NameID needs this check, but this
// package does not enforce it: an ephemeral or step-up-only flow may want
// a transient NameID on purpose.
func (a *Assertion) IsTransient() bool {
	if a == nil {
		return false
	}
	return strings.Contains(a.NameIDFormat, "transient")
}
