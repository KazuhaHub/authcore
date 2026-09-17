package saml

import (
	"bytes"
	"encoding/xml"
	"fmt"

	dsig "github.com/russellhaering/goxmldsig"
)

// This file inspects the raw, not-yet-trust-decided Response XML with a
// plain streaming token scanner (encoding/xml.Decoder), deliberately
// BEFORE any signature is checked. Every check here is "shape of the
// document", never "content of a value crewjam already extracted" — the
// two must stay independent, or a bug in one would just be reproduced in
// the other.

// allowedSignatureMethods and allowedDigestMethods are the SHA-256-or-
// better algorithms this package accepts. This is an ALLOWLIST, not a
// denylist: an algorithm identifier nobody here has evaluated is refused
// by default, not accepted by omission. Values are goxmldsig's own
// constants (a real, direct dependency already, via crewjam/saml) so a
// future rename upstream cannot silently widen this policy.
var (
	allowedSignatureMethods = map[string]bool{
		dsig.RSASHA256SignatureMethod:   true,
		dsig.RSASHA384SignatureMethod:   true,
		dsig.RSASHA512SignatureMethod:   true,
		dsig.ECDSASHA256SignatureMethod: true,
		dsig.ECDSASHA384SignatureMethod: true,
		dsig.ECDSASHA512SignatureMethod: true,
	}
	// goxmldsig does not export digest method identifiers, so these are
	// the plain W3C URIs.
	allowedDigestMethods = map[string]bool{
		"http://www.w3.org/2001/04/xmlenc#sha256":       true,
		"http://www.w3.org/2001/04/xmldsig-more#sha384": true,
		"http://www.w3.org/2001/04/xmlenc#sha512":       true,
	}
)

const (
	samlAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
	samlProtocolNS  = "urn:oasis:names:tc:SAML:2.0:protocol"
)

// responseShape is what countAssertions and requireDestination both need
// from one pass over the document, gathered together so a caller only
// tokenizes the (potentially attacker-controlled) XML once.
type responseShape struct {
	rootIsResponse        bool
	destination           string
	hasDestinationAttr    bool
	assertionCount        int  // direct children of the root: Assertion + EncryptedAssertion
	hasEncryptedAssertion bool // true if any counted assertion was EncryptedAssertion
}

// scanResponseShape walks raw as a token stream and reports its top-level
// structure. It does not validate well-formedness beyond what the decoder
// itself enforces, and it does not look inside nested elements other than
// counting immediate children of the root — it exists to answer
// structural questions cheaply, not to replace crewjam's own parsing.
func scanResponseShape(raw []byte) (responseShape, error) {
	var shape responseShape
	dec := xml.NewDecoder(bytes.NewReader(raw))
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch el := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 1 {
				if el.Name.Local != "Response" {
					return shape, fmt.Errorf("%w: root element is %q, not Response", ErrMalformedResponse, el.Name.Local)
				}
				shape.rootIsResponse = true
				for _, a := range el.Attr {
					if a.Name.Local == "Destination" {
						shape.hasDestinationAttr = true
						shape.destination = a.Value
					}
				}
			}
			if depth == 2 && el.Name.Space == samlAssertionNS && (el.Name.Local == "Assertion" || el.Name.Local == "EncryptedAssertion") {
				shape.assertionCount++
				if el.Name.Local == "EncryptedAssertion" {
					shape.hasEncryptedAssertion = true
				}
			}
		case xml.EndElement:
			depth--
		}
	}
	if !shape.rootIsResponse {
		return shape, fmt.Errorf("%w: no root Response element found", ErrMalformedResponse)
	}
	return shape, nil
}

// scanWeakSignatureAlgorithms reports the first disallowed SignatureMethod
// or DigestMethod Algorithm found ANYWHERE in the document (the outer
// Response signature, the Assertion signature, and every Reference
// digest), so a strong outer algorithm can never vouch for a weak inner
// one. Returns "" if every algorithm found is on the allowlist (including
// the case where the document has no signature at all — an absent
// signature is a different failure, caught elsewhere).
func scanWeakSignatureAlgorithms(raw []byte) (badElement, badAlgorithm string) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", ""
		}
		el, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		var allowed map[string]bool
		switch el.Name.Local {
		case dsig.SignatureMethodTag:
			allowed = allowedSignatureMethods
		case dsig.DigestMethodTag:
			allowed = allowedDigestMethods
		default:
			continue
		}
		for _, a := range el.Attr {
			if a.Name.Local == dsig.AlgorithmAttr && !allowed[a.Value] {
				return el.Name.Local, a.Value
			}
		}
	}
}
