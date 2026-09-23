package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"html"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// This file builds a real, fully-functional crewjam/saml IdentityProvider
// for tests, so "a legitimate assertion must validate" and "a tampered one
// must not" are exercised against genuine XML-DSig signatures rather than
// hand-typed fixtures. All hostnames use RFC 2606 reserved TLDs
// (example.com/.org/.net) and no data here refers to a real IdP or SP.

// testKeyPair returns a fresh RSA-2048 self-signed keypair for cn.
func testKeyPair(t testing.TB, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return key, cert
}

// testIdP wraps a crewjam IdentityProvider configured to issue an
// assertion for a single, fixed SP (spEntityID / spACSURL / spCert),
// carrying a fixed session (nameID etc.), on demand.
type testIdP struct {
	idp        *crewjamsaml.IdentityProvider
	entityID   string
	spEntityID string
	spACSURL   string
	spCert     *x509.Certificate
	nameID     string
	nameIDFmt  string
	userEmail  string
	groups     []string
	// customAttributes are emitted verbatim, which is how a case controls the
	// exact Name/FriendlyName pairs an assertion carries.
	customAttributes []crewjamsaml.Attribute
}

func newTestIdP(t testing.TB, spEntityID, spACSURL string, spCert *x509.Certificate) *testIdP {
	t.Helper()
	key, cert := testKeyPair(t, "idp.example.com")
	idpEntityID := "https://idp.example.com/saml/metadata"

	tp := &testIdP{
		entityID:   idpEntityID,
		spEntityID: spEntityID,
		spACSURL:   spACSURL,
		spCert:     spCert,
		nameID:     "subject-001@idp.example.com",
		nameIDFmt:  string(crewjamsaml.EmailAddressNameIDFormat),
		userEmail:  "subject-001@idp.example.com",
		groups:     []string{"engineering", "sso-test"},
	}

	idp := &crewjamsaml.IdentityProvider{
		Key:         key,
		Certificate: cert,
		MetadataURL: mustParseURL(t, idpEntityID),
		SSOURL:      mustParseURL(t, "https://idp.example.com/saml/sso"),
		// crewjam defaults to rsa-sha1 (dsig.RSASHA1SignatureMethod) when
		// this is left unset. Real IdPs that still do that are exactly
		// what Config.RejectWeakSignatures exists to refuse (see
		// TestValidateResponseXML_WeakSignatureAlgorithm); every other
		// test in this package wants a realistic, currently-acceptable
		// algorithm instead.
		SignatureMethod:         dsig.RSASHA256SignatureMethod,
		ServiceProviderProvider: tp,
		SessionProvider:         tp,
	}
	tp.idp = idp
	return tp
}

func mustParseURL(t testing.TB, raw string) url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return *u
}

// GetServiceProvider implements crewjamsaml.ServiceProviderProvider.
func (tp *testIdP) GetServiceProvider(_ *http.Request, serviceProviderID string) (*crewjamsaml.EntityDescriptor, error) {
	if serviceProviderID != tp.spEntityID {
		return nil, os.ErrNotExist
	}
	certStr := certToBase64(tp.spCert)
	isDefault := true
	return &crewjamsaml.EntityDescriptor{
		EntityID: tp.spEntityID,
		SPSSODescriptors: []crewjamsaml.SPSSODescriptor{
			{
				SSODescriptor: crewjamsaml.SSODescriptor{
					RoleDescriptor: crewjamsaml.RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []crewjamsaml.KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: crewjamsaml.KeyInfo{
									X509Data: crewjamsaml.X509Data{
										X509Certificates: []crewjamsaml.X509Certificate{{Data: certStr}},
									},
								},
							},
						},
					},
				},
				AssertionConsumerServices: []crewjamsaml.IndexedEndpoint{
					{Binding: crewjamsaml.HTTPPostBinding, Location: tp.spACSURL, Index: 0, IsDefault: &isDefault},
				},
			},
		},
	}, nil
}

// GetSession implements crewjamsaml.SessionProvider. Always returns the
// same canned session; there is no login form in these tests.
func (tp *testIdP) GetSession(_ http.ResponseWriter, _ *http.Request, _ *crewjamsaml.IdpAuthnRequest) *crewjamsaml.Session {
	return &crewjamsaml.Session{
		ID:               "session-001",
		CreateTime:       time.Now(),
		ExpireTime:       time.Now().Add(time.Hour),
		Index:            "session-index-001",
		NameID:           tp.nameID,
		NameIDFormat:     tp.nameIDFmt,
		UserEmail:        tp.userEmail,
		Groups:           tp.groups,
		CustomAttributes: tp.customAttributes,
	}
}

func certToBase64(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

// idpInitiatedResponse drives ServeIDPInitiated and returns the raw,
// base64-decoded <Response> XML it produced — a genuinely signed document,
// not a hand-built fixture.
func (tp *testIdP) idpInitiatedResponse(t testing.TB) []byte {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/idp-initiated", nil)
	rec := httptest.NewRecorder()
	tp.idp.ServeIDPInitiated(rec, req, tp.spEntityID, "")
	if rec.Code != http.StatusOK && rec.Code != 0 {
		t.Fatalf("ServeIDPInitiated: status %d body %s", rec.Code, rec.Body.String())
	}
	return extractSAMLResponse(t, rec.Body.String())
}

// ssoResponse drives ServeSSO with a real AuthnRequest (built the same way
// Provider.NewAuthnRequest builds one) and returns the raw, decoded
// <Response> XML. Used for the InResponseTo / SP-initiated-flow tests.
func (tp *testIdP) ssoResponse(t *testing.T, authnRequestURL string) []byte {
	t.Helper()
	u, err := url.Parse(authnRequestURL)
	if err != nil {
		t.Fatalf("parse authn request url: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/sso?"+u.RawQuery, nil)
	rec := httptest.NewRecorder()
	tp.idp.ServeSSO(rec, req)
	if rec.Code != http.StatusOK && rec.Code != 0 {
		t.Fatalf("ServeSSO: status %d body %s", rec.Code, rec.Body.String())
	}
	return extractSAMLResponse(t, rec.Body.String())
}

// extractSAMLResponse pulls the SAMLResponse hidden-input value out of
// crewjam's default auto-submit HTML form and base64-decodes it.
func extractSAMLResponse(t testing.TB, page string) []byte {
	t.Helper()
	const marker = `name="SAMLResponse" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("no SAMLResponse field in IdP output: %s", page)
	}
	rest := page[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("unterminated SAMLResponse field: %s", page)
	}
	// crewjam's default response form template renders through
	// html/template, which HTML-entity-escapes the attribute value
	// (notably '+' -> "&#43;", a defense against legacy UTF-7 sniffing).
	// Undo that before base64-decoding.
	b64 := html.UnescapeString(rest[:j])
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode SAMLResponse: %v", err)
	}
	return decoded
}

// testSP builds a Provider (and the underlying crewjam SP identity it
// needs) pointed at idp. Returns the Provider plus its own SP entity ID /
// ACS URL / certificate, for feeding into newTestIdP.
type testSPMaterial struct {
	entityID string
	acsURL   string
	key      *rsa.PrivateKey
	cert     *x509.Certificate
}

func newTestSPMaterial(t testing.TB, name string) testSPMaterial {
	t.Helper()
	key, cert := testKeyPair(t, name+".example.org")
	return testSPMaterial{
		entityID: fmt.Sprintf("https://%s.example.org/saml/metadata", name),
		acsURL:   fmt.Sprintf("https://%s.example.org/saml/acs", name),
		key:      key,
		cert:     cert,
	}
}

func newTestProvider(t *testing.T, sp testSPMaterial, idpMeta *crewjamsaml.EntityDescriptor, mutate func(*Config)) *Provider {
	t.Helper()
	cfg := Config{
		EntityID:    sp.entityID,
		ACSURL:      sp.acsURL,
		Key:         sp.key,
		Certificate: sp.cert,
		IDPMetadata: idpMeta,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}
