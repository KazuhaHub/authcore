package saml

import (
	"strings"
	"testing"

	crewjamsaml "github.com/crewjam/saml"
)

func TestNew_RequiredFields(t *testing.T) {
	idpMeta := &crewjamsaml.EntityDescriptor{EntityID: "https://idp.example.com/saml/metadata"}

	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing EntityID", Config{ACSURL: "https://sp.example.org/acs", IDPMetadata: idpMeta}},
		{"missing ACSURL", Config{EntityID: "https://sp.example.org/metadata", IDPMetadata: idpMeta}},
		{"missing IDPMetadata", Config{EntityID: "https://sp.example.org/metadata", ACSURL: "https://sp.example.org/acs"}},
		{"unparseable ACSURL", Config{EntityID: "https://sp.example.org/metadata", ACSURL: "://not a url", IDPMetadata: idpMeta}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestNew_KeyCertificateMustBePaired(t *testing.T) {
	idpMeta := &crewjamsaml.EntityDescriptor{EntityID: "https://idp.example.com/saml/metadata"}
	sp := newTestSPMaterial(t, "keypair")

	_, err := New(Config{
		EntityID:    sp.entityID,
		ACSURL:      sp.acsURL,
		IDPMetadata: idpMeta,
		Key:         sp.key,
		// Certificate deliberately omitted.
	})
	if err == nil {
		t.Fatal("expected an error when Key is set without Certificate")
	}
}

func TestProvider_MetadataXML(t *testing.T) {
	sp := newTestSPMaterial(t, "metadata")
	idpMeta := &crewjamsaml.EntityDescriptor{EntityID: "https://idp.example.com/saml/metadata"}
	p := newTestProvider(t, sp, idpMeta, nil)

	doc, err := p.MetadataXML()
	if err != nil {
		t.Fatalf("MetadataXML: %v", err)
	}
	s := string(doc)
	if !strings.Contains(s, sp.entityID) {
		t.Errorf("metadata does not contain EntityID %q:\n%s", sp.entityID, s)
	}
	if !strings.Contains(s, sp.acsURL) {
		t.Errorf("metadata does not contain ACS URL %q:\n%s", sp.acsURL, s)
	}
}

func TestProvider_NewAuthnRequest(t *testing.T) {
	sp := newTestSPMaterial(t, "authnreq")
	idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)
	p := newTestProvider(t, sp, idp.idp.Metadata(), nil)

	req, err := p.NewAuthnRequest("relay-xyz")
	if err != nil {
		t.Fatalf("NewAuthnRequest: %v", err)
	}
	if req.ID == "" {
		t.Error("AuthnRequest.ID is empty")
	}
	if !strings.Contains(req.RedirectURL, "idp.example.com") {
		t.Errorf("RedirectURL = %q, want it to target the IdP SSO endpoint", req.RedirectURL)
	}
	if !strings.Contains(req.RedirectURL, "SAMLRequest=") {
		t.Errorf("RedirectURL = %q, missing SAMLRequest query param", req.RedirectURL)
	}
	if !strings.Contains(req.RedirectURL, "RelayState=relay-xyz") {
		t.Errorf("RedirectURL = %q, missing expected RelayState", req.RedirectURL)
	}
}

func TestProvider_NewAuthnRequest_NoIDPMetadata(t *testing.T) {
	p := &Provider{}
	if _, err := p.NewAuthnRequest(""); err == nil {
		t.Fatal("expected an error from a Provider with no crewjam ServiceProvider, got nil")
	}
}

func TestProvider_NotConfigured(t *testing.T) {
	var p *Provider
	if _, err := p.NewAuthnRequest(""); err != ErrNotConfigured {
		t.Errorf("nil Provider.NewAuthnRequest: err = %v, want ErrNotConfigured", err)
	}
}
