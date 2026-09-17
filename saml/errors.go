package saml

import "errors"

// Sentinel errors returned by this package. Callers can match them with
// errors.Is; the underlying crewjam/saml error (when there is one) is always
// wrapped so its detail is not lost.
var (
	// ErrNotConfigured is returned by any Provider method when New failed
	// to build a usable crewjam ServiceProvider (e.g. IDPMetadata was nil).
	ErrNotConfigured = errors.New("saml: provider not configured")

	// ErrMissingAssertionID is returned when a validated assertion carries
	// no ID. SAML core (2.3.3) requires an Assertion to have an ID; an
	// empty one would silently bypass the replay cache, so it is treated
	// as a hard failure rather than a assertion the cache ignores.
	ErrMissingAssertionID = errors.New("saml: assertion has no ID")

	// ErrReplayed is returned when ValidateResponse(XML) sees an
	// assertion ID it has already accepted within its acceptance window.
	ErrReplayed = errors.New("saml: assertion already consumed (replay)")

	// ErrTooManyAssertions is returned when a Response carries more than
	// one top-level Assertion/EncryptedAssertion element. crewjam/saml
	// silently picks the first assertion that parses and validates; on
	// its own that is a wrapping vector (GHSA-j2jp-wvqg-wc2g class:
	// smuggle a second, differently-trusted assertion alongside a
	// legitimate one). This package refuses the whole response instead.
	ErrTooManyAssertions = errors.New("saml: response contains more than one assertion")

	// ErrMissingDestination is returned when RequireDestination is true
	// (the default) and the Response has no Destination attribute.
	// crewjam only enforces Destination when the Response itself is
	// signed OR the attribute is present; an attacker can omit it on an
	// unsigned Response (still valid when only the Assertion is signed)
	// to skip the check entirely. This package closes that gap.
	ErrMissingDestination = errors.New("saml: response has no Destination")

	// ErrDestinationMismatch is returned when the Response's Destination
	// attribute does not equal this Provider's configured ACS URL.
	ErrDestinationMismatch = errors.New("saml: response Destination does not match the ACS URL")

	// ErrWeakSignatureAlgorithm is returned when RejectWeakSignatures is
	// true (the default) and the response declares a SignatureMethod or
	// DigestMethod outside the SHA-256-or-better allowlist (most notably
	// rsa-sha1, ADFS's and legacy Keycloak's historical default).
	ErrWeakSignatureAlgorithm = errors.New("saml: response uses a weak signature or digest algorithm")

	// ErrEncryptedAssertionNotAllowed is returned when the Response
	// carries an EncryptedAssertion and AllowEncryptedAssertions is
	// false (the default).
	ErrEncryptedAssertionNotAllowed = errors.New("saml: response contains an encrypted assertion, which is not allowed by this provider's configuration")

	// ErrDuplicateAttribute is returned when StrictAttributes is true and
	// the same attribute Name (or FriendlyName) is declared by more than
	// one distinct <Attribute> element in the assertion.
	ErrDuplicateAttribute = errors.New("saml: assertion declares the same attribute name more than once")

	// ErrResponseTooLarge is returned when the decoded response XML (or,
	// for a redirect-bound message, the inflated payload) exceeds the
	// configured size limit.
	ErrResponseTooLarge = errors.New("saml: response exceeds the maximum allowed size")

	// ErrMalformedResponse is returned when the response cannot be
	// interpreted as a single top-level SAML <Response> element at all
	// (not valid XML, empty, wrong root element, ...).
	ErrMalformedResponse = errors.New("saml: response is not a well-formed SAML Response")
)
