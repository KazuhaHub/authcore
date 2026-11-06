package saml

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

func TestSignedAmbiguousAssertionIdentityIsRejected(t *testing.T) {
	for _, change := range []string{"missing-issuer", "foreign-nameid"} {
		t.Run(change, func(t *testing.T) {
			sp := newTestSPMaterial(t, change)
			idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)
			provider := newTestProvider(t, sp, idp.idp.Metadata(), func(c *Config) { c.AllowIDPInitiated = true })
			document := etree.NewDocument()
			original := idp.idpInitiatedResponse(t)
			if _, err := provider.ValidateResponseXML(context.Background(), original, url.URL{}, nil); err != nil {
				t.Fatal("original signed assertion must remain acceptable", err)
			}
			if err := document.ReadFromBytes(original); err != nil {
				t.Fatal(err)
			}
			root := document.Root()
			assertion := root.SelectElement("Assertion")
			if assertion == nil {
				t.Fatal("signed fixture has no assertion")
			}
			for _, element := range assertion.ChildElements() {
				if element.Tag == "Signature" {
					assertion.RemoveChild(element)
				}
			}
			if change == "missing-issuer" {
				assertion.RemoveChild(assertion.SelectElement("Issuer"))
			} else {
				name := assertion.SelectElement("Subject").SelectElement("NameID")
				name.Space = "foreign"
				name.CreateAttr("xmlns:foreign", "urn:foreign")
			}
			signing := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{
				Certificate: [][]byte{idp.idp.Certificate.Raw}, PrivateKey: idp.idp.Key,
			}))
			signing.IdAttribute = "ID"
			signing.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
			if err := signing.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
				t.Fatal(err)
			}
			for _, element := range root.ChildElements() {
				if element.Tag == "Signature" {
					root.RemoveChild(element)
				}
			}
			signed, err := signing.SignEnveloped(root.Copy())
			if err != nil {
				t.Fatal(err)
			}
			document.SetRoot(signed)
			raw, err := document.WriteToBytes()
			if err != nil {
				t.Fatal(err)
			}
			wire := etree.NewDocument()
			// Reparse the wire bytes before verification so etree records the
			// appended signature's parent, as it does for a received response.
			if err := wire.ReadFromBytes(raw); err != nil {
				t.Fatal(err)
			}
			verification := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{idp.idp.Certificate}})
			verification.IdAttribute = "ID"
			if _, err := verification.Validate(wire.Root()); err != nil {
				t.Fatal("mutated fixture must carry a genuine valid signature", err)
			}
			if change == "foreign-nameid" {
				parsed, err := provider.sp.ParseXMLResponse(raw, nil, url.URL{})
				if err == nil && parsed.Subject != nil && parsed.Subject.NameID != nil {
					t.Fatal("dependency admitted a foreign-namespace NameID")
				}
			}
			_, err = provider.ValidateResponseXML(context.Background(), raw, url.URL{}, nil)
			if !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("expected malformed assertion refusal, got %v", err)
			}
		})
	}
}
