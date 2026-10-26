package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

func signedRequestConfig(t *testing.T, key crypto.Signer, cert *x509.Certificate, required bool) Config {
	t.Helper()
	return Config{EntityID: "https://sp.example.com/metadata", ACSURL: "https://sp.example.com/acs", Key: key, Certificate: cert,
		IDPMetadata: &crewjamsaml.EntityDescriptor{EntityID: "https://idp.example.com", IDPSSODescriptors: []crewjamsaml.IDPSSODescriptor{{
			WantAuthnRequestsSigned: &required, SingleSignOnServices: []crewjamsaml.Endpoint{{Binding: crewjamsaml.HTTPRedirectBinding, Location: "https://idp.example.com/sso?tenant=one&theme=dark"}},
		}}}}
}

func verifyAuthnSignature(t *testing.T, key crypto.PublicKey, target *url.URL) bool {
	t.Helper()
	query := target.Query()
	message := "SAMLRequest=" + url.QueryEscape(query.Get("SAMLRequest"))
	if _, present := query["RelayState"]; present {
		message += "&RelayState=" + url.QueryEscape(query.Get("RelayState"))
	}
	message += "&SigAlg=" + url.QueryEscape(query.Get("SigAlg"))
	signature, err := base64.StdEncoding.DecodeString(query.Get("Signature"))
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(message))
	switch key := key.(type) {
	case *rsa.PublicKey:
		return query.Get("SigAlg") == dsig.RSASHA256SignatureMethod && rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) == nil
	case *ecdsa.PublicKey:
		width := (key.Params().N.BitLen() + 7) / 8
		if query.Get("SigAlg") != dsig.ECDSASHA256SignatureMethod || len(signature) != width*2 {
			return false
		}
		return ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(signature[:width]), new(big.Int).SetBytes(signature[width:]))
	default:
		return false
	}
}

func TestSignedAuthnRequestsUseSHA256AndBindingOctets(t *testing.T) {
	rsaKey, rsaCert := testKeyPair(t, "signed-request.example.com")
	for _, kind := range []string{"rsa", "p256", "p384", "p521"} {
		t.Run(kind, func(t *testing.T) {
			var key crypto.Signer = rsaKey
			cert := rsaCert
			if kind != "rsa" {
				curve := map[string]elliptic.Curve{"p256": elliptic.P256(), "p384": elliptic.P384(), "p521": elliptic.P521()}[kind]
				ec, err := ecdsa.GenerateKey(curve, rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				key = ec
				template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
				raw, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
				if err != nil {
					t.Fatal(err)
				}
				cert, err = x509.ParseCertificate(raw)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, required := range []bool{true, false} {
				config := signedRequestConfig(t, key, cert, required)
				config.SignAuthnRequests = !required
				provider, err := New(config)
				if err != nil {
					t.Fatal(err)
				}
				if signed := provider.Metadata().SPSSODescriptors[0].AuthnRequestsSigned; signed == nil || !*signed {
					t.Fatal("SP metadata did not advertise signed requests")
				}
				for _, relay := range []string{"", "opaque &injected=true+%/?续期"} {
					request, err := provider.NewAuthnRequest(relay)
					if err != nil {
						t.Fatal(err)
					}
					target, err := url.Parse(request.RedirectURL)
					if err != nil {
						t.Fatal(err)
					}
					if target.Query().Get("RelayState") != relay || target.Query().Get("injected") != "" || target.Query().Get("tenant") != "one" || !verifyAuthnSignature(t, cert.PublicKey, target) {
						t.Fatal("signed binding lost state, endpoint query or cryptographic verification")
					}
					// Endpoint query fields are not part of the binding's signed octets.
					query := target.Query()
					query.Set("theme", "changed")
					target.RawQuery = query.Encode()
					if !verifyAuthnSignature(t, cert.PublicKey, target) {
						t.Fatal("endpoint query leaked into binding signature")
					}
					for _, name := range []string{"SAMLRequest", "RelayState", "SigAlg", "Signature"} {
						changed := *target
						values := changed.Query()
						values.Set(name, values.Get(name)+"tampered")
						changed.RawQuery = values.Encode()
						if verifyAuthnSignature(t, cert.PublicKey, &changed) {
							t.Fatal("tampered signed request accepted", name)
						}
					}
				}
			}
		})
	}
}

func TestUnsignedAuthnRequestEscapesRelayStateAndRefusesBindingCollisions(t *testing.T) {
	key, cert := testKeyPair(t, "unsigned-request.example.com")
	config := signedRequestConfig(t, key, cert, false)
	provider, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	relay := "value &injected=true+%"
	request, err := provider.NewAuthnRequest(relay)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse(request.RedirectURL)
	if target.Query().Get("RelayState") != relay || target.Query().Get("injected") != "" || target.Query().Has("Signature") || target.Query().Has("SigAlg") {
		t.Fatal("default request changed signing policy or allowed RelayState parameter injection")
	}
	if _, err := provider.NewAuthnRequest(strings.Repeat("x", 80)); err != nil {
		t.Fatal("maximum binding RelayState was refused", err)
	}
	if _, err := provider.NewAuthnRequest(strings.Repeat("x", 81)); err == nil {
		t.Fatal("binding RelayState byte limit was not enforced")
	}
	for _, name := range []string{"SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature"} {
		config := signedRequestConfig(t, key, cert, false)
		config.IDPMetadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location += "&" + name + "=existing"
		provider, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := provider.NewAuthnRequest("opaque"); err == nil {
			t.Fatal("endpoint already contained a reserved binding parameter", name)
		}
	}
}

func TestSignedAuthnRequestRequiresMatchingStrongKeyMaterial(t *testing.T) {
	key, cert := testKeyPair(t, "request-key.example.com")
	_, otherCert := testKeyPair(t, "other-request-key.example.com")
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &weak.PublicKey, weak)
	if err != nil {
		t.Fatal(err)
	}
	weakCert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []bool{true, false} {
		for name, change := range map[string]func(*Config){
			"no key pair":            func(c *Config) { c.Key = nil; c.Certificate = nil },
			"mismatched certificate": func(c *Config) { c.Certificate = otherCert },
			"weak RSA":               func(c *Config) { c.Key = weak; c.Certificate = weakCert },
			"typed nil RSA":          func(c *Config) { c.Key = (*rsa.PrivateKey)(nil) },
			"typed nil EC":           func(c *Config) { c.Key = (*ecdsa.PrivateKey)(nil) },
			"empty certificate":      func(c *Config) { c.Certificate = &x509.Certificate{} },
		} {
			config := signedRequestConfig(t, key, cert, required)
			config.SignAuthnRequests = !required
			change(&config)
			if provider, err := New(config); err == nil || provider != nil {
				t.Fatal("invalid signing material accepted", name)
			}
		}
	}
}
