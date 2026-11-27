package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/url"
	"strings"
	"testing"

	crewjamsaml "github.com/crewjam/saml"
)

// requestOf decodes the AuthnRequest of an HTTP-Redirect URL.
func requestOf(t *testing.T, redirect string) crewjamsaml.AuthnRequest {
	t.Helper()
	target, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	deflated, err := base64.StdEncoding.DecodeString(target.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	if err != nil {
		t.Fatal(err)
	}
	var req crewjamsaml.AuthnRequest
	if err := xml.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	return req
}

// The subject hint goes into the request's <Subject><NameID>, signed with the
// rest when requests are signed; a hint that is not one short line is not
// sent, and without one the request has no Subject.
func TestAuthnRequestCarriesTheSubjectHint(t *testing.T) {
	key, cert := testKeyPair(t, "subject-hint.example.com")
	for _, signed := range []bool{false, true} {
		provider, err := New(signedRequestConfig(t, key, cert, signed))
		if err != nil {
			t.Fatal(err)
		}
		request, err := provider.NewAuthnRequestWith("relay", AuthnOptions{SubjectHint: "tang@acme.example"})
		if err != nil {
			t.Fatal(err)
		}
		req := requestOf(t, request.RedirectURL)
		if req.Subject == nil || req.Subject.NameID == nil || req.Subject.NameID.Value != "tang@acme.example" ||
			req.Subject.NameID.Format != string(crewjamsaml.EmailAddressNameIDFormat) || req.ID != request.ID {
			t.Fatalf("signed %v: %+v", signed, req.Subject)
		}
		target, _ := url.Parse(request.RedirectURL)
		if signed && !verifyAuthnSignature(t, key.Public(), target) {
			t.Fatal("the request with a subject is not signed over it")
		}
		request, err = provider.NewAuthnRequestWith("relay", AuthnOptions{SubjectHint: "u-123", SubjectHintFormat: crewjamsaml.PersistentNameIDFormat})
		if err != nil {
			t.Fatal(err)
		}
		if req := requestOf(t, request.RedirectURL); req.Subject.NameID.Format != string(crewjamsaml.PersistentNameIDFormat) {
			t.Fatalf("%+v", req.Subject.NameID)
		}
	}
	provider, err := New(signedRequestConfig(t, key, cert, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, hint := range []string{"", "a\nb@acme.example", strings.Repeat("a", 257), "\xff@acme.example"} {
		request, err := provider.NewAuthnRequestWith("relay", AuthnOptions{SubjectHint: hint})
		if err != nil {
			t.Fatal(err)
		}
		if req := requestOf(t, request.RedirectURL); req.Subject != nil {
			t.Fatalf("%q was sent: %+v", hint, req.Subject.NameID)
		}
	}
	request, err := provider.NewAuthnRequest("relay")
	if err != nil {
		t.Fatal(err)
	}
	if req := requestOf(t, request.RedirectURL); req.Subject != nil {
		t.Fatal("a Subject without a hint")
	}
}
