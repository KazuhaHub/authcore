package saml

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	crewjamsaml "github.com/crewjam/saml"
)

// TestValidateResponseXML_Baseline is the "a legitimate assertion must be
// accepted" case every other negative test in this file is a variation of:
// a genuinely signed IdP-initiated Response, from a real crewjam
// IdentityProvider, must validate and produce the expected neutral
// Assertion fields.
func TestValidateResponseXML_Baseline(t *testing.T) {
	sp := newTestSPMaterial(t, "baseline")
	idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)

	p := newTestProvider(t, sp, idp.idp.Metadata(), func(c *Config) {
		c.AllowIDPInitiated = true
	})

	raw := idp.idpInitiatedResponse(t)

	a, err := p.ValidateResponseXML(context.Background(), raw, url.URL{}, nil)
	if err != nil {
		t.Fatalf("ValidateResponseXML: %v", err)
	}
	if a.NameID != idp.nameID {
		t.Errorf("NameID = %q, want %q", a.NameID, idp.nameID)
	}
	if a.Issuer != idp.entityID {
		t.Errorf("Issuer = %q, want %q", a.Issuer, idp.entityID)
	}
	if a.ID == "" {
		t.Error("ID is empty")
	}
	if a.SessionIndex != "session-index-001" {
		t.Errorf("SessionIndex = %q, want session-index-001", a.SessionIndex)
	}
	if got := a.Attribute("urn:oid:0.9.2342.19200300.100.1.3"); got != idp.userEmail {
		t.Errorf("mail attribute = %q, want %q", got, idp.userEmail)
	}
	if got := a.Attribute("urn:oid:1.3.6.1.4.1.5923.1.1.1.1"); got != "engineering" {
		t.Errorf("first group attribute value = %q, want engineering", got)
	}
	if a.NotOnOrAfter.IsZero() {
		t.Error("NotOnOrAfter is zero")
	}
}

// TestValidateResponse_SPInitiated exercises the full SP-initiated path:
// Provider.NewAuthnRequest builds a real AuthnRequest, the test IdP answers
// it via ServeSSO (checking InResponseTo itself), and
// Provider.ValidateResponse (the *http.Request-based entry point, as real
// HTTP handlers use it) must accept the result.
func TestValidateResponse_SPInitiated(t *testing.T) {
	sp := newTestSPMaterial(t, "spinit")
	idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)
	p := newTestProvider(t, sp, idp.idp.Metadata(), nil)

	authnReq, err := p.NewAuthnRequest("relay-1")
	if err != nil {
		t.Fatalf("NewAuthnRequest: %v", err)
	}
	if authnReq.ID == "" {
		t.Fatal("AuthnRequest.ID is empty")
	}

	raw := idp.ssoResponse(t, authnReq.RedirectURL)

	r := postACSRequest(t, sp.acsURL, raw)
	a, err := p.ValidateResponse(context.Background(), r, []string{authnReq.ID})
	if err != nil {
		t.Fatalf("ValidateResponse: %v", err)
	}
	if a.NameID != idp.nameID {
		t.Errorf("NameID = %q, want %q", a.NameID, idp.nameID)
	}

	// A DIFFERENT (wrong) possibleRequestIDs must be rejected: this is
	// crewjam's own InResponseTo check, exercised through our wrapper.
	r2 := postACSRequest(t, sp.acsURL, raw)
	if _, err := p.ValidateResponse(context.Background(), r2, []string{"some-other-request-id"}); err == nil {
		t.Fatal("expected InResponseTo mismatch to be rejected, got nil error")
	}
}

func postACSRequest(t *testing.T, acsURL string, rawXML []byte) *http.Request {
	t.Helper()
	form := url.Values{}
	form.Set("SAMLResponse", base64.StdEncoding.EncodeToString(rawXML))
	r := httptest.NewRequest(http.MethodPost, acsURL, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// TestValidateResponseXML_TamperedSignature: flipping a byte inside the
// signed Assertion (the NameID value) must be rejected — the signature no
// longer matches the digest crewjam recomputes.
func TestValidateResponseXML_TamperedSignature(t *testing.T) {
	sp := newTestSPMaterial(t, "tamper")
	idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)
	p := newTestProvider(t, sp, idp.idp.Metadata(), func(c *Config) { c.AllowIDPInitiated = true })

	raw := idp.idpInitiatedResponse(t)
	tampered := []byte(strings.Replace(string(raw), idp.nameID, "attacker@evil.example.com", 1))
	if string(tampered) == string(raw) {
		t.Fatal("tamper did not change anything — test is broken")
	}

	_, err := p.ValidateResponseXML(context.Background(), tampered, url.URL{}, nil)
	if err == nil {
		t.Fatal("expected tampered signature to be rejected, got nil error")
	}
}

// TestValidateResponseXML_MultipleAssertions: a Response smuggling a
// second Assertion element alongside the legitimate, validly-signed one
// must be rejected outright (ErrTooManyAssertions), regardless of whether
// the second one is itself well-formed or signed. This is the
// GHSA-j2jp-wvqg-wc2g class of defense this package adds.
func TestValidateResponseXML_MultipleAssertions(t *testing.T) {
	sp := newTestSPMaterial(t, "multi")
	idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)
	p := newTestProvider(t, sp, idp.idp.Metadata(), func(c *Config) { c.AllowIDPInitiated = true })

	raw := idp.idpInitiatedResponse(t)

	// Duplicate the entire <saml:Assertion>...</saml:Assertion> block and
	// insert the copy right after the original, still inside <Response>.
	const openTag = `<saml:Assertion`
	start := strings.Index(string(raw), openTag)
	if start < 0 {
		t.Fatalf("no <saml:Assertion in response: %s", raw)
	}
	end := strings.Index(string(raw), `</saml:Assertion>`)
	if end < 0 {
		t.Fatalf("no closing </saml:Assertion> in response: %s", raw)
	}
	end += len(`</saml:Assertion>`)
	assertionBlock := string(raw)[start:end]
	doubled := string(raw)[:end] + assertionBlock + string(raw)[end:]

	_, err := p.ValidateResponseXML(context.Background(), []byte(doubled), url.URL{}, nil)
	if !errors.Is(err, ErrTooManyAssertions) {
		t.Fatalf("err = %v, want ErrTooManyAssertions", err)
	}
}

// TestValidateResponseXML_DestinationMismatch: a Response whose
// Destination does not match the Provider's ACS URL must be rejected, and
// with RequireDestination at its default (true), a Response with NO
// Destination attribute at all must also be rejected — closing the gap
// where crewjam only enforces Destination when the Response is signed or
// the attribute happens to be present.
func TestValidateResponseXML_DestinationMismatch(t *testing.T) {
	sp := newTestSPMaterial(t, "dest")
	idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)
	p := newTestProvider(t, sp, idp.idp.Metadata(), func(c *Config) { c.AllowIDPInitiated = true })

	raw := string(idp.idpInitiatedResponse(t))
	wrongDest := strings.Replace(raw, `Destination="`+sp.acsURL+`"`, `Destination="https://not-this-sp.example.org/acs"`, 1)
	if wrongDest == raw {
		t.Fatal("Destination replace did not match — test is broken")
	}

	_, err := p.ValidateResponseXML(context.Background(), []byte(wrongDest), url.URL{}, nil)
	if !errors.Is(err, ErrDestinationMismatch) {
		t.Fatalf("err = %v, want ErrDestinationMismatch", err)
	}

	missingDest := strings.Replace(raw, `Destination="`+sp.acsURL+`"`, ``, 1)
	if missingDest == raw {
		t.Fatal("Destination removal did not match — test is broken")
	}
	_, err = p.ValidateResponseXML(context.Background(), []byte(missingDest), url.URL{}, nil)
	if !errors.Is(err, ErrMissingDestination) {
		t.Fatalf("err = %v, want ErrMissingDestination", err)
	}
}

// TestValidateResponseXML_AudienceMismatch: an assertion honestly issued
// for a DIFFERENT SP's entity ID (so its signature is untouched and
// perfectly valid) must be rejected by this Provider, which is configured
// with its own, different EntityID. This exercises crewjam's own audience
// check through the orchestration layer, with no raw-XML tampering
// involved (tampering the signed Audience value would just turn this into
// another signature-tamper test).
func TestValidateResponseXML_AudienceMismatch(t *testing.T) {
	spA := newTestSPMaterial(t, "audience-a")
	spB := newTestSPMaterial(t, "audience-b")
	// The IdP issues assertions audienced for spA...
	idp := newTestIdP(t, spA.entityID, spA.acsURL, spA.cert)
	// ...but we validate them as spB, a different EntityID.
	p := newTestProvider(t, spB, idp.idp.Metadata(), func(c *Config) {
		c.AllowIDPInitiated = true
		// Destination in the assertion targets spA's ACS URL, not spB's;
		// disable that check here so only the audience check is exercised.
		c.RequireDestination = Bool(false)
	})

	raw := idp.idpInitiatedResponse(t)
	_, err := p.ValidateResponseXML(context.Background(), raw, url.URL{}, nil)
	if err == nil {
		t.Fatal("expected audience mismatch to be rejected, got nil error")
	}
}

// TestValidateResponseXML_Replay: the same assertion presented twice must
// succeed once and fail the second time, and this must hold even when the
// two presentations race concurrently — exactly the "captured
// SAMLResponse replayed by an attacker racing the real login" scenario.
func TestValidateResponseXML_Replay(t *testing.T) {
	sp := newTestSPMaterial(t, "replay")
	idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)
	p := newTestProvider(t, sp, idp.idp.Metadata(), func(c *Config) { c.AllowIDPInitiated = true })

	raw := idp.idpInitiatedResponse(t)

	if _, err := p.ValidateResponseXML(context.Background(), raw, url.URL{}, nil); err != nil {
		t.Fatalf("first validation: %v", err)
	}
	_, err := p.ValidateResponseXML(context.Background(), raw, url.URL{}, nil)
	if !errors.Is(err, ErrReplayed) {
		t.Fatalf("second validation err = %v, want ErrReplayed", err)
	}
}

func TestValidateResponseXML_ReplayConcurrent(t *testing.T) {
	sp := newTestSPMaterial(t, "replayrace")
	idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)
	p := newTestProvider(t, sp, idp.idp.Metadata(), func(c *Config) { c.AllowIDPInitiated = true })

	raw := idp.idpInitiatedResponse(t)

	const n = 32
	var wg sync.WaitGroup
	var okCount, replayedCount, otherErrCount int32
	var mu sync.Mutex
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := p.ValidateResponseXML(context.Background(), raw, url.URL{}, nil)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				okCount++
			case errors.Is(err, ErrReplayed):
				replayedCount++
			default:
				otherErrCount++
			}
		}()
	}
	wg.Wait()

	if okCount != 1 {
		t.Errorf("okCount = %d, want exactly 1", okCount)
	}
	if replayedCount != n-1 {
		t.Errorf("replayedCount = %d, want %d", replayedCount, n-1)
	}
	if otherErrCount != 0 {
		t.Errorf("otherErrCount = %d, want 0", otherErrCount)
	}
}

// TestValidateResponseXML_ReplayStillRejectedAfterExpiry: once the replay
// cache's own TTL for an assertion has lapsed, a THIRD presentation of the
// same ID is not treated as "new" in any way that matters — because by
// that point the assertion's own NotOnOrAfter (which the TTL was sized to
// outlive, see Provider.expiryFor) has also lapsed, so crewjam's
// independent time-window check rejects it regardless of what the replay
// cache says. This test pins that invariant directly against the cache.
func TestValidateResponseXML_ReplayStillRejectedAfterExpiry(t *testing.T) {
	sp := newTestSPMaterial(t, "replayexpiry")
	idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)

	// A clock the test controls, shared by the Provider (for computing
	// cache expiry) AND by crewjam/saml itself (crewjam's own signature/
	// time-window validation reads the package var crewjamsaml.TimeNow,
	// not any per-call parameter) so "the assertion is now actually
	// expired" and "the cache's TTL for it has lapsed" move together, the
	// same way they would for a real clock advancing.
	now := time.Now()
	clock := func() time.Time { return now }
	origTimeNow := crewjamsaml.TimeNow
	crewjamsaml.TimeNow = clock
	t.Cleanup(func() { crewjamsaml.TimeNow = origTimeNow })

	p := newTestProvider(t, sp, idp.idp.Metadata(), func(c *Config) {
		c.AllowIDPInitiated = true
		c.Clock = clock
	})

	raw := idp.idpInitiatedResponse(t)
	if _, err := p.ValidateResponseXML(context.Background(), raw, url.URL{}, nil); err != nil {
		t.Fatalf("first validation: %v", err)
	}

	// Move the clock well past both the assertion's real NotOnOrAfter
	// (MaxIssueDelay, 90s from crewjam) and the replay cache's TTL
	// (NotOnOrAfter + MaxClockSkew + ReplayExpiryMargin).
	now = now.Add(2 * time.Hour)

	_, err := p.ValidateResponseXML(context.Background(), raw, url.URL{}, nil)
	if err == nil {
		t.Fatal("expected the now-expired assertion to still be rejected, got nil error")
	}
	if errors.Is(err, ErrReplayed) {
		t.Fatal("expected rejection via crewjam's own expiry check, not the replay cache (which would report the same ID as not-yet-seen once its own TTL elapsed)")
	}
}

// TestValidateResponseXML_MissingAssertion covers the "zero assertions"
// edge of the same structural check that rejects more than one.
func TestValidateResponseXML_MissingAssertion(t *testing.T) {
	sp := newTestSPMaterial(t, "noassert")
	idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)
	p := newTestProvider(t, sp, idp.idp.Metadata(), func(c *Config) { c.AllowIDPInitiated = true })

	raw := string(idp.idpInitiatedResponse(t))
	start := strings.Index(raw, `<saml:Assertion`)
	end := strings.Index(raw, `</saml:Assertion>`) + len(`</saml:Assertion>`)
	stripped := raw[:start] + raw[end:]

	_, err := p.ValidateResponseXML(context.Background(), []byte(stripped), url.URL{}, nil)
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("err = %v, want ErrMalformedResponse", err)
	}
}
