package saml

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	crewjamsaml "github.com/crewjam/saml"
)

// ValidateResponse validates an HTTP-POST-binding SAMLResponse carried on
// r (a POST request to this Provider's ACS endpoint) and returns the
// resulting Assertion. possibleRequestIDs should contain the AuthnRequest
// ID(s) issued for this login (see AuthnRequest.ID); pass nil only when
// Config.AllowIDPInitiated is true and no matching request is expected.
//
// r.URL is used as the "current URL" crewjam compares the Response's
// Destination against (see Config.RequireDestination for why this package
// checks it independently too). r.Body is NOT size-limited by this
// function — bound it yourself (e.g. http.MaxBytesReader) before calling
// ParseForm on r, the same way you would for any other POST handler; this
// package separately caps the size of the decoded XML it will parse (see
// Config.MaxResponseBytes), which is a different concern from bounding
// the raw HTTP body.
func (p *Provider) ValidateResponse(ctx context.Context, r *http.Request, possibleRequestIDs []string) (*Assertion, error) {
	if p == nil || p.sp == nil {
		return nil, ErrNotConfigured
	}
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("saml: parse form: %w", err)
	}
	raw := r.PostForm.Get("SAMLResponse")
	if raw == "" {
		return nil, fmt.Errorf("saml: request has no SAMLResponse field")
	}
	// Some IdPs (Entra among them) wrap the base64 payload at 76 columns
	// (MIME style); base64.StdEncoding rejects embedded whitespace, so
	// strip it before decoding.
	raw = stripBase64Whitespace(raw)
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("saml: decode SAMLResponse base64: %w", err)
	}
	return p.validate(ctx, decoded, *r.URL, possibleRequestIDs)
}

// ValidateResponseXML validates an already-decoded (not base64, not
// compressed) Response document — e.g. for a caller that received the
// SAMLResponse some other way than a standard POST-binding *http.Request,
// or one that wants to decode the HTTP layer itself. currentURL is
// compared against the Response's Destination exactly as ValidateResponse
// does.
func (p *Provider) ValidateResponseXML(ctx context.Context, decoded []byte, currentURL url.URL, possibleRequestIDs []string) (*Assertion, error) {
	if p == nil || p.sp == nil {
		return nil, ErrNotConfigured
	}
	return p.validate(ctx, decoded, currentURL, possibleRequestIDs)
}

// ValidateRedirectResponse validates a Response delivered via the SAML
// HTTP-Redirect binding: base64-decoded and then DEFLATE-inflated under a
// hard size cap (see InflateLimited) before any XML parsing happens, so a
// decompression bomb is rejected before it can consume memory. Most
// deployments never receive a Response this way (POST binding is what all
// three projects this package was built from use), but the binding is
// valid per the SAML spec for small, typically-unsigned responses, and an
// IdP or a caller building SP-to-SP forwarding may use it.
func (p *Provider) ValidateRedirectResponse(ctx context.Context, rawQueryParam string, currentURL url.URL, possibleRequestIDs []string) (*Assertion, error) {
	if p == nil || p.sp == nil {
		return nil, ErrNotConfigured
	}
	decoded, err := DecodeRedirectMessage(rawQueryParam, p.cfg.maxInflatedBytes())
	if err != nil {
		return nil, err
	}
	return p.validate(ctx, decoded, currentURL, possibleRequestIDs)
}

func stripBase64Whitespace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t':
			return -1
		}
		return r
	}, s)
}

// validate runs every check this package adds around crewjam/saml's own
// parsing, in the order that matters for defense-in-depth: cheap
// structural checks that need no cryptography run first (size, shape,
// algorithm allowlist, Destination), so a hostile payload is rejected as
// early as possible; only a document that passes all of them is handed to
// crewjam for signature and condition validation; only an assertion
// crewjam accepts is checked against the replay cache.
func (p *Provider) validate(ctx context.Context, decoded []byte, currentURL url.URL, possibleRequestIDs []string) (*Assertion, error) {
	cfg := p.cfg

	if int64(len(decoded)) > cfg.maxResponseBytes() {
		return nil, fmt.Errorf("%w (%d bytes)", ErrResponseTooLarge, len(decoded))
	}

	shape, err := scanResponseShape(decoded)
	if err != nil {
		return nil, err
	}
	if shape.assertionCount == 0 {
		return nil, fmt.Errorf("%w: no Assertion or EncryptedAssertion element found", ErrMalformedResponse)
	}
	if shape.assertionCount > 1 {
		return nil, ErrTooManyAssertions
	}

	if cfg.requireDestination() {
		if !shape.hasDestinationAttr || shape.destination == "" {
			return nil, ErrMissingDestination
		}
		if shape.destination != cfg.ACSURL {
			return nil, fmt.Errorf("%w: got %q, want %q", ErrDestinationMismatch, shape.destination, cfg.ACSURL)
		}
	} else if shape.hasDestinationAttr && shape.destination != "" && shape.destination != cfg.ACSURL {
		// Even with the stricter "must be present" rule relaxed, a
		// Destination that IS present and wrong is never acceptable —
		// crewjam enforces this too, but failing fast here keeps the
		// error consistent regardless of signature state.
		return nil, fmt.Errorf("%w: got %q, want %q", ErrDestinationMismatch, shape.destination, cfg.ACSURL)
	}

	if cfg.rejectWeakSignatures() {
		if el, alg := scanWeakSignatureAlgorithms(decoded); el != "" {
			return nil, fmt.Errorf("%w: %s uses %q", ErrWeakSignatureAlgorithm, el, alg)
		}
	}

	if !cfg.AllowEncryptedAssertions && shape.hasEncryptedAssertion {
		return nil, ErrEncryptedAssertionNotAllowed
	}

	assertion, err := p.sp.ParseXMLResponse(decoded, possibleRequestIDs, currentURL)
	if err != nil {
		return nil, fmt.Errorf("saml: %w", err)
	}
	if assertion.ID == "" {
		return nil, ErrMissingAssertionID
	}

	out, err := assertionFromCrewjam(assertion, cfg.StrictAttributes)
	if err != nil {
		return nil, err
	}

	expiresAt := p.expiryFor(assertion)
	now := cfg.now()
	seen, err := p.cache.SeenOrAdd(ctx, out.ID, expiresAt, now)
	if err != nil {
		return nil, fmt.Errorf("saml: replay cache: %w", err)
	}
	if seen {
		return nil, ErrReplayed
	}

	return out, nil
}

// expiryFor computes how long an assertion's ID must be remembered by the
// replay cache: the latest of its Conditions.NotOnOrAfter and every
// SubjectConfirmationData.NotOnOrAfter (crewjam enforces both, so an
// attacker gets the benefit of whichever is later), plus crewjam's own
// MaxClockSkew (crewjam accepts the assertion until NotOnOrAfter+skew, so
// the cache must outlive that too) plus Config.ReplayExpiryMargin.
func (p *Provider) expiryFor(a *crewjamsaml.Assertion) time.Time {
	now := p.cfg.now()
	latest := now.Add(5 * time.Minute) // sensible floor if the assertion is oddly missing both
	if a.Conditions != nil && !a.Conditions.NotOnOrAfter.IsZero() && a.Conditions.NotOnOrAfter.After(latest) {
		latest = a.Conditions.NotOnOrAfter
	}
	if a.Subject != nil {
		for _, sc := range a.Subject.SubjectConfirmations {
			if sc.SubjectConfirmationData != nil && !sc.SubjectConfirmationData.NotOnOrAfter.IsZero() {
				if sc.SubjectConfirmationData.NotOnOrAfter.After(latest) {
					latest = sc.SubjectConfirmationData.NotOnOrAfter
				}
			}
		}
	}
	return latest.Add(crewjamsaml.MaxClockSkew).Add(p.cfg.replayExpiryMargin())
}
