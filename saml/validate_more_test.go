package saml

import (
	"context"
	"errors"
	"net/url"
	"testing"

	crewjamsaml "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// TestValidateResponseXML_WeakSignatureAlgorithm: an IdP still signing
// with rsa-sha1 (crewjam's own default, and ADFS's historical default)
// must be rejected when RejectWeakSignatures is at its default (true).
func TestValidateResponseXML_WeakSignatureAlgorithm(t *testing.T) {
	sp := newTestSPMaterial(t, "weaksig")
	idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)
	idp.idp.SignatureMethod = dsig.RSASHA1SignatureMethod // crewjam's own default; set explicitly for clarity

	p := newTestProvider(t, sp, idp.idp.Metadata(), func(c *Config) { c.AllowIDPInitiated = true })

	raw := idp.idpInitiatedResponse(t)
	_, err := p.ValidateResponseXML(context.Background(), raw, url.URL{}, nil)
	if !errors.Is(err, ErrWeakSignatureAlgorithm) {
		t.Fatalf("err = %v, want ErrWeakSignatureAlgorithm", err)
	}

	// With the policy explicitly relaxed, the same response must pass —
	// proves the rejection above was really about the algorithm policy,
	// not some other difference (e.g. a broken signature).
	p2 := newTestProvider(t, sp, idp.idp.Metadata(), func(c *Config) {
		c.AllowIDPInitiated = true
		c.RejectWeakSignatures = Bool(false)
	})
	if _, err := p2.ValidateResponseXML(context.Background(), raw, url.URL{}, nil); err != nil {
		t.Fatalf("with RejectWeakSignatures=false: %v", err)
	}
}

// TestValidateResponseXML_StrictAttributes: the same attribute Name
// declared by two distinct <Attribute> elements is accepted by default and
// refused when Config.StrictAttributes is true.
//
// This exercises assertionFromCrewjam directly against a hand-built
// crewjamsaml.Assertion (no signature involved) rather than mutating a
// real signed response's XML: doubling an <Attribute> element inside a
// signed Assertion also breaks its signature, which would make the test
// exercise signature rejection instead of the attribute-collision policy
// it is meant to isolate.
func TestValidateResponseXML_StrictAttributes(t *testing.T) {
	a := &crewjamsaml.Assertion{
		AttributeStatements: []crewjamsaml.AttributeStatement{
			{Attributes: []crewjamsaml.Attribute{
				{Name: "mail", Values: []crewjamsaml.AttributeValue{{Value: "a@example.com"}}},
				{Name: "mail", Values: []crewjamsaml.AttributeValue{{Value: "b@example.com"}}},
			}},
		},
	}
	if _, err := assertionFromCrewjam(a, false); err != nil {
		t.Fatalf("StrictAttributes=false must accept a repeated Attribute Name: %v", err)
	}
	if _, err := assertionFromCrewjam(a, true); !errors.Is(err, ErrDuplicateAttribute) {
		t.Fatalf("StrictAttributes=true: err = %v, want ErrDuplicateAttribute", err)
	}

	// A single <Attribute> with several <AttributeValue> children (the
	// normal multi-valued case) must never trip StrictAttributes.
	multiValued := &crewjamsaml.Assertion{
		AttributeStatements: []crewjamsaml.AttributeStatement{
			{Attributes: []crewjamsaml.Attribute{
				{Name: "groups", Values: []crewjamsaml.AttributeValue{{Value: "a"}, {Value: "b"}}},
			}},
		},
	}
	if _, err := assertionFromCrewjam(multiValued, true); err != nil {
		t.Fatalf("multi-valued attribute must be accepted under StrictAttributes: %v", err)
	}
}

// TestValidateResponseXML_StrictAttributesEndToEnd confirms the same
// policy holds through the full Provider.ValidateResponseXML path (not
// just the assertionFromCrewjam unit above) on a real signed response —
// which legitimately has NO duplicated attribute Name, so it must pass
// with StrictAttributes turned on.
func TestValidateResponseXML_StrictAttributesEndToEnd(t *testing.T) {
	sp := newTestSPMaterial(t, "strictattre2e")
	idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)
	p := newTestProvider(t, sp, idp.idp.Metadata(), func(c *Config) {
		c.AllowIDPInitiated = true
		c.StrictAttributes = true
	})
	raw := idp.idpInitiatedResponse(t)
	if _, err := p.ValidateResponseXML(context.Background(), raw, url.URL{}, nil); err != nil {
		t.Fatalf("ValidateResponseXML with StrictAttributes=true: %v", err)
	}
}

// encryptedOnlyResponse is a Response whose only assertion is an
// EncryptedAssertion. It is never decrypted, so the ciphertext is a stand-in.
const encryptedOnlyResponse = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://sp.example.org/acs">
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:EncryptedAssertion>
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">
      <xenc:CipherData><xenc:CipherValue>YWJjZA==</xenc:CipherValue></xenc:CipherData>
    </xenc:EncryptedData>
  </saml:EncryptedAssertion>
</samlp:Response>`

// TestValidateResponseXML_EncryptedAssertionRejectedByDefault confirms
// that a Response whose only assertion is an EncryptedAssertion is
// refused unless AllowEncryptedAssertions is set — exercised through the
// structural scanner directly (scanResponseShape), since building a real
// encrypted assertion end-to-end belongs to crewjam's own test suite and
// this package's own contribution is the refusal policy layered on top of
// crewjam's ability to decrypt one.
func TestValidateResponseXML_EncryptedAssertionRejectedByDefault(t *testing.T) {
	shape, err := scanResponseShape([]byte(encryptedOnlyResponse))
	if err != nil {
		t.Fatalf("scanResponseShape: %v", err)
	}
	if shape.assertionCount != 1 {
		t.Fatalf("assertionCount = %d, want 1", shape.assertionCount)
	}
	if !shape.hasEncryptedAssertion {
		t.Fatal("hasEncryptedAssertion = false, want true")
	}

	sp := newTestSPMaterial(t, "encassert")
	// A minimal self-consistent Provider just to run the pre-crewjam
	// checks in validate(); ParseXMLResponse is never reached because
	// the encrypted-assertion refusal fires first.
	idpMeta := &crewjamsaml.EntityDescriptor{EntityID: "https://idp.example.com/saml/metadata"}
	p := newTestProvider(t, sp, idpMeta, func(c *Config) {
		c.ACSURL = "https://sp.example.org/acs"
	})
	_, err = p.ValidateResponseXML(context.Background(), []byte(encryptedOnlyResponse), url.URL{}, nil)
	if !errors.Is(err, ErrEncryptedAssertionNotAllowed) {
		t.Fatalf("err = %v, want ErrEncryptedAssertionNotAllowed", err)
	}
}
