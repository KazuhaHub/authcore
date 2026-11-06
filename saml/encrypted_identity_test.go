package saml

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/beevik/etree"
	"github.com/crewjam/saml/xmlenc"
	dsig "github.com/russellhaering/goxmldsig"
)

func TestEncryptedAssertionIdentityAdmission(t *testing.T) {
	for _, change := range []string{"valid", "foreign-nameid", "missing-subject", "missing-conditions", "missing-confirmation-data"} {
		t.Run(change, func(t *testing.T) {
			sp := newTestSPMaterial(t, "encrypted-identity")
			idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)
			provider := newTestProvider(t, sp, idp.idp.Metadata(), func(c *Config) {
				c.AllowIDPInitiated = true
				c.AllowEncryptedAssertions = true
			})
			document := etree.NewDocument()
			if err := document.ReadFromBytes(idp.idpInitiatedResponse(t)); err != nil {
				t.Fatal(err)
			}
			root := document.Root()
			assertion := root.SelectElement("Assertion")
			for _, parent := range []*etree.Element{root, assertion} {
				for _, child := range parent.ChildElements() {
					if child.Tag == "Signature" {
						parent.RemoveChild(child)
					}
				}
			}
			switch change {
			case "foreign-nameid":
				name := assertion.SelectElement("Subject").SelectElement("NameID")
				name.Space = "foreign"
				name.CreateAttr("xmlns:foreign", "urn:foreign")
			case "missing-subject":
				assertion.RemoveChild(assertion.SelectElement("Subject"))
			case "missing-conditions":
				assertion.RemoveChild(assertion.SelectElement("Conditions"))
			case "missing-confirmation-data":
				confirmation := assertion.SelectElement("Subject").SelectElement("SubjectConfirmation")
				confirmation.RemoveChild(confirmation.SelectElement("SubjectConfirmationData"))
			}
			plaintext := etree.NewDocument()
			plaintext.SetRoot(assertion.Copy())
			plainBytes, err := plaintext.WriteToBytes()
			if err != nil {
				t.Fatal(err)
			}
			// Use an existing supported legacy transport for this identity
			// regression. The fixture does not select production encryption
			// policy; its outer signature remains RSA-SHA256.
			encrypter := xmlenc.PKCS1v15()
			encrypter.BlockCipher = xmlenc.AES128CBC
			encrypted, err := encrypter.Encrypt(sp.cert, plainBytes, nil)
			if err != nil {
				t.Fatal(err)
			}
			root.RemoveChild(assertion)
			wrapper := root.CreateElement("saml:EncryptedAssertion")
			wrapper.CreateAttr("xmlns:saml", samlAssertionNS)
			wrapper.AddChild(encrypted)
			signing := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{
				Certificate: [][]byte{idp.idp.Certificate.Raw}, PrivateKey: idp.idp.Key,
			}))
			signing.IdAttribute = "ID"
			signing.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
			if err := signing.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
				t.Fatal(err)
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
			if err := wire.ReadFromBytes(raw); err != nil {
				t.Fatal(err)
			}
			verification := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{idp.idp.Certificate}})
			verification.IdAttribute = "ID"
			if _, err := verification.Validate(wire.Root()); err != nil {
				t.Fatal("encrypted fixture must carry a genuine trusted outer signature", err)
			}
			got, err := provider.ValidateResponseXML(context.Background(), raw, url.URL{}, nil)
			if change == "valid" {
				if err != nil || got.NameID != idp.nameID {
					t.Fatal("genuine signed and encrypted identity did not survive", err)
				}
			} else if change == "foreign-nameid" {
				if err == nil && got.NameID != "" {
					t.Fatal("encrypted foreign-namespace NameID became an authenticated identity")
				}
			} else if err == nil {
				t.Fatal("encrypted missing required element was admitted")
			}
		})
	}
}
