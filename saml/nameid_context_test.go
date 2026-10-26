package saml

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	crewjamsaml "github.com/crewjam/saml"
)

type qualifiedNameIDMaker struct {
	issuer, sp, alias string
}

func (m qualifiedNameIDMaker) MakeAssertion(request *crewjamsaml.IdpAuthnRequest, session *crewjamsaml.Session) error {
	if err := (crewjamsaml.DefaultAssertionMaker{}).MakeAssertion(request, session); err != nil {
		return err
	}
	name := request.Assertion.Subject.NameID
	name.NameQualifier = m.issuer
	name.SPNameQualifier = m.sp
	name.SPProvidedID = m.alias
	return nil
}

func TestValidatedNameIDContext(t *testing.T) {
	for _, transport := range []string{"xml", "post"} {
		for _, present := range []bool{true, false} {
			name := transport + "/absent"
			if present {
				name = transport + "/qualified"
			}
			t.Run(name, func(t *testing.T) {
				sp := newTestSPMaterial(t, "qualified-name")
				idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)
				idp.nameIDFmt = string(crewjamsaml.PersistentNameIDFormat)
				maker := qualifiedNameIDMaker{}
				if present {
					maker = qualifiedNameIDMaker{issuer: idp.entityID, sp: sp.entityID, alias: "  stable SP alias  "}
				}
				idp.idp.AssertionMaker = maker
				provider := newTestProvider(t, sp, idp.idp.Metadata(), nil)
				authn, err := provider.NewAuthnRequest("opaque-relay-context")
				if err != nil {
					t.Fatal(err)
				}
				raw := idp.ssoResponse(t, authn.RedirectURL)
				validate := func(provider *Provider, document []byte) (*Assertion, error) {
					if transport == "xml" {
						return provider.ValidateResponseXML(context.Background(), document, url.URL{}, []string{authn.ID})
					}
					body := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(document)}, "RelayState": {"opaque-relay-context"}}
					request := httptest.NewRequest(http.MethodPost, sp.acsURL, strings.NewReader(body.Encode()))
					request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					return provider.ValidateResponse(context.Background(), request, []string{authn.ID})
				}
				assertion, err := validate(provider, raw)
				if err != nil {
					t.Fatal("signed SP-initiated assertion failed", err)
				}
				if assertion.NameID != idp.nameID || assertion.NameIDFormat != idp.nameIDFmt || assertion.NameQualifier != maker.issuer || assertion.SPNameQualifier != maker.sp || assertion.SPProvidedID != maker.alias {
					t.Fatal("validated NameID context was lost or normalized")
				}
				if !present {
					return
				}
				for _, attribute := range []string{"NameQualifier", "SPNameQualifier", "SPProvidedID"} {
					marker := []byte(" " + attribute + "=\"")
					if bytes.Count(raw, marker) != 1 {
						t.Fatal("signed fixture did not contain one NameID attribute", attribute)
					}
					start := bytes.Index(raw, marker) + len(marker)
					end := start + bytes.IndexByte(raw[start:], '"')
					tampered := append([]byte(nil), raw[:start]...)
					tampered = append(tampered, []byte("different-name-context")...)
					tampered = append(tampered, raw[end:]...)
					// A fresh cache ensures this refusal is not merely replay detection.
					fresh := newTestProvider(t, sp, idp.idp.Metadata(), nil)
					if got, err := validate(fresh, tampered); err == nil || got != nil {
						t.Fatal("tampered signed NameID context was exposed", attribute)
					}
				}
			})
		}
	}
}

func TestMissingNameIDContextStaysEmpty(t *testing.T) {
	for _, subject := range []*crewjamsaml.Subject{nil, {}} {
		assertion, err := assertionFromCrewjam(&crewjamsaml.Assertion{Subject: subject}, false)
		if err != nil {
			t.Fatal(err)
		}
		if assertion.NameQualifier != "" || assertion.SPNameQualifier != "" || assertion.SPProvidedID != "" {
			t.Fatal("missing NameID context was invented")
		}
	}
}
