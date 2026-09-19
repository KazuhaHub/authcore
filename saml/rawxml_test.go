package saml

import (
	"fmt"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
)

// The algorithm tables are an ALLOWLIST: anything not listed is refused. These
// pin their exact contents, because a consumer that copies them verbatim (PSP
// does, for the pre-verification check it runs against the same documents) is
// bound by the same list — widening it here would silently widen a check on the
// other side of the boundary too.
func TestAllowedSignatureMethodsAreExactlyThese(t *testing.T) {
	want := []string{
		dsig.RSASHA256SignatureMethod,
		dsig.RSASHA384SignatureMethod,
		dsig.RSASHA512SignatureMethod,
		dsig.ECDSASHA256SignatureMethod,
		dsig.ECDSASHA384SignatureMethod,
		dsig.ECDSASHA512SignatureMethod,
	}
	if len(allowedSignatureMethods) != len(want) {
		t.Fatalf("allowedSignatureMethods holds %d entries, want %d — adding or removing one changes what every consumer accepts", len(allowedSignatureMethods), len(want))
	}
	for _, uri := range want {
		if !allowedSignatureMethods[uri] {
			t.Errorf("allowedSignatureMethods is missing %q", uri)
		}
	}
}

func TestAllowedDigestMethodsAreExactlyThese(t *testing.T) {
	want := []string{
		"http://www.w3.org/2001/04/xmlenc#sha256",
		"http://www.w3.org/2001/04/xmldsig-more#sha384",
		"http://www.w3.org/2001/04/xmlenc#sha512",
	}
	if len(allowedDigestMethods) != len(want) {
		t.Fatalf("allowedDigestMethods holds %d entries, want %d", len(allowedDigestMethods), len(want))
	}
	for _, uri := range want {
		if !allowedDigestMethods[uri] {
			t.Errorf("allowedDigestMethods is missing %q", uri)
		}
	}

	// Called out separately because it is the entry a reader is most likely to
	// "fix": xmlenc#sha384 is a real W3C digest URI and its absence looks like an
	// oversight. It is not — a consumer's own hardening line refuses documents
	// that declare it, so accepting it here would mean this package validating a
	// response that consumer rejects, for no gain to anyone. Adding it is a
	// deliberate cross-repository change, not a typo fix.
	if allowedDigestMethods["http://www.w3.org/2001/04/xmlenc#sha384"] {
		t.Error("xmlenc#sha384 was added to allowedDigestMethods; that widens a check consumers enforce on their side, so it has to be a deliberate change with them, not a local one")
	}
}

// The tables are only policy if the scan consults them, so this drives the
// scanner: every accepted algorithm passes, and a representative refused
// algorithm does not.
func TestScanWeakSignatureAlgorithms_ConsultsTheAllowlists(t *testing.T) {
	declaration := func(element, algorithm string) []byte {
		return []byte(fmt.Sprintf(`<?xml version="1.0"?><Root><%s Algorithm=%q/></Root>`, element, algorithm))
	}

	accepted := map[string][]string{
		"SignatureMethod": {
			dsig.RSASHA256SignatureMethod, dsig.RSASHA384SignatureMethod, dsig.RSASHA512SignatureMethod,
			dsig.ECDSASHA256SignatureMethod, dsig.ECDSASHA384SignatureMethod, dsig.ECDSASHA512SignatureMethod,
		},
		"DigestMethod": {
			"http://www.w3.org/2001/04/xmlenc#sha256",
			"http://www.w3.org/2001/04/xmldsig-more#sha384",
			"http://www.w3.org/2001/04/xmlenc#sha512",
		},
	}
	for element, algorithms := range accepted {
		for _, algorithm := range algorithms {
			if el, got := scanWeakSignatureAlgorithms(declaration(element, algorithm)); el != "" {
				t.Errorf("%s %q was refused as weak (%s)", element, algorithm, got)
			}
		}
	}

	refused := map[string][]string{
		"SignatureMethod": {
			dsig.RSASHA1SignatureMethod,
			"http://www.w3.org/2000/09/xmldsig#dsa-sha1",
			"http://www.w3.org/2000/09/xmldsig#hmac-sha1",
			"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
			"http://www.w3.org/2001/04/xmldsig-more#md5",
			"http://example.com/not-an-algorithm",
			"",
		},
		"DigestMethod": {
			"http://www.w3.org/2000/09/xmlenc#sha1",
			"http://www.w3.org/2000/09/xmldsig#sha1",
			"http://www.w3.org/2001/04/xmldsig-more#md5",
			"http://www.w3.org/2001/04/xmlenc#sha384",
			"http://example.com/not-an-algorithm",
			"",
		},
	}
	for element, algorithms := range refused {
		for _, algorithm := range algorithms {
			if el, _ := scanWeakSignatureAlgorithms(declaration(element, algorithm)); el == "" {
				t.Errorf("%s %q was accepted; the allowlist is not being consulted", element, algorithm)
			}
		}
	}
}
