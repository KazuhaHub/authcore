package saml

import (
	"bytes"
	"strings"
	"testing"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// FuzzScanResponseShapeMatchesCrewjam holds the shape scan to the parser it
// guards. validate() refuses a Response unless scanResponseShape counts
// exactly one Assertion or EncryptedAssertion under the root, and that is the
// GHSA-j2jp-wvqg-wc2g defence: handed several, crewjam returns the first one
// that verifies. But the scan resolves namespaces the encoding/xml way, and
// crewjam finds its assertions another way, through etree and goxmldsig's
// etreeutils. A document the two read differently, one assertion to the scan
// and two to crewjam, passes the rule and still hands crewjam a choice. The
// same holds for the EncryptedAssertion refusal.
//
// Only disagreements in that direction fail. The scan counting more than
// crewjam, or a document either side refuses, is safe: validate() stops there.
//
// The seeds are what the tests already use: a response signed by the test
// IdP, the same response with its assertion duplicated (the shape an
// attacker starts from), and the encrypted-only response. `go test` runs just
// these on every push; weekly.yml fuzzes from them for a bounded time.
func FuzzScanResponseShapeMatchesCrewjam(f *testing.F) {
	sp := newTestSPMaterial(f, "fuzz")
	idp := newTestIdP(f, sp.entityID, sp.acsURL, sp.cert)
	signed := idp.idpInitiatedResponse(f)
	f.Add(signed)
	f.Add(withAssertionDuplicated(f, signed))
	f.Add([]byte(encryptedOnlyResponse))

	f.Fuzz(func(t *testing.T, raw []byte) {
		shape, err := scanResponseShape(raw)
		if err != nil || shape.assertionCount != 1 {
			return
		}
		count, encrypted, ok := crewjamAssertions(raw)
		if !ok {
			return
		}
		if count > 1 {
			t.Fatalf("the shape scan counts one assertion, crewjam finds %d", count)
		}
		if encrypted && !shape.hasEncryptedAssertion {
			t.Fatal("crewjam finds an EncryptedAssertion the shape scan does not, so AllowEncryptedAssertions=false would not refuse it")
		}
	})
}

// crewjamAssertions reports which children of the root crewjam/saml v0.5.1
// treats as assertions, by the path ParseXMLResponse takes before any
// signature matters: xml-roundtrip-validator, then etree, then findChildren,
// which matches a child's tag and resolves its prefix through etreeutils
// (service_provider.go). ok is false wherever crewjam gives up first. It
// leaves out crewjam's checks on the Response element itself, which do not
// change which children count. Keep it in step with crewjam when that moves.
func crewjamAssertions(raw []byte) (count int, encrypted, ok bool) {
	if xrv.Validate(bytes.NewReader(raw)) != nil {
		return 0, false, false
	}
	doc := etree.NewDocument()
	if doc.ReadFromBytes(raw) != nil || doc.Root() == nil {
		return 0, false, false
	}
	for _, tag := range []string{"EncryptedAssertion", "Assertion"} {
		for _, el := range doc.Root().ChildElements() {
			if el.Tag != tag {
				continue
			}
			ctx, err := etreeutils.NSBuildParentContext(el)
			if err == nil {
				ctx, err = ctx.SubContext(el)
			}
			var ns string
			if err == nil {
				ns, err = ctx.LookupPrefix(el.Space)
			}
			if err != nil {
				return 0, false, false // findChildren returns it, and crewjam stops
			}
			if ns == samlAssertionNS {
				count++
				encrypted = encrypted || tag == "EncryptedAssertion"
			}
		}
	}
	return count, encrypted, true
}

// withAssertionDuplicated inserts a copy of the first <saml:Assertion> block
// right after it, as TestValidateResponseXML_MultipleAssertions does.
func withAssertionDuplicated(tb testing.TB, raw []byte) []byte {
	tb.Helper()
	doc := string(raw)
	start := strings.Index(doc, "<saml:Assertion")
	end := strings.Index(doc, "</saml:Assertion>")
	if start < 0 || end < start {
		tb.Fatalf("no <saml:Assertion> block in the test IdP's response: %s", raw)
	}
	end += len("</saml:Assertion>")
	return []byte(doc[:end] + doc[start:end] + doc[end:])
}
