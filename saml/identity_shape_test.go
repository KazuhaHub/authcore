package saml

import (
	"errors"
	"testing"
)

func TestPlaintextIdentityNamespacesAndCounts(t *testing.T) {
	prefix := `<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:f="urn:foreign"><s:Assertion>`
	suffix := `</s:Assertion></p:Response>`
	valid := `<s:Issuer>idp</s:Issuer><s:Subject><s:NameID>original</s:NameID></s:Subject>`
	if err := validatePlaintextIdentityShape([]byte(prefix + valid + suffix)); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`<s:Subject><s:NameID>original</s:NameID></s:Subject>`,
		`<f:Issuer>idp</f:Issuer><s:Subject><s:NameID>original</s:NameID></s:Subject>`,
		`<s:Issuer>idp</s:Issuer><s:Issuer>idp</s:Issuer>`,
		`<s:Issuer>idp</s:Issuer><s:Subject><f:NameID>spoof</f:NameID></s:Subject>`,
		`<s:Issuer>idp</s:Issuer><s:Subject><NameID>spoof</NameID></s:Subject>`,
		`<s:Issuer>idp</s:Issuer><s:Subject><s:NameID>original</s:NameID><f:NameID>spoof</f:NameID></s:Subject>`,
		`<s:Issuer>idp</s:Issuer><f:Subject><f:NameID>spoof</f:NameID></f:Subject>`,
	} {
		if err := validatePlaintextIdentityShape([]byte(prefix + body + suffix)); !errors.Is(err, ErrMalformedResponse) {
			t.Errorf("ambiguous plaintext identity was admitted: %v", err)
		}
	}
}
