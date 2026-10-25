# OIDC authorization-code orchestration

`New` validates HTTPS discovery and configures `go-oidc/v3` and `x/oauth2` for
authorization-code flows. `Begin` generates independent state, nonce and PKCE
material. `Complete` checks the supplied state, configuration binding, S256
verifier, ID-token signature/issuer/audience/expiry, nonce, authorized party and
any advertised access-token hash. It returns neutral verified claims and omits token-endpoint access and refresh
credentials.

This package is unreleased until a verified tag includes it; v0.6.2 does not.

## Caller integration

1. Construct a provider from trusted configuration. Supply an HTTP client with
   the required TLS roots and network policy. Configuration is copied at
   construction; metadata returned by `Metadata` is an independent copy.
2. Call `Begin`. Before redirecting to its URL, privately persist all four
   `State` fields with a short expiry, provider eligibility and a binding to the
   initiating browser. Default JSON intentionally omits these fields. Use explicit
   private storage columns or a purpose-built private codec.
3. On callback, reject duplicate/ambiguous parameters and failed browser binding.
   Atomically consume the stored state after checking its expiry, then pass it,
   the returned state value and authorization code to `Complete`. Consumption
   must survive restart and concurrent callbacks. The library itself has no state
   store, browser cookie, one-use callback ledger or account transaction.
4. Map the verified issuer/subject and explicitly decoded claims according to the
   application. An `email_verified` string is not a boolean: use an appropriate
   claim schema and reject failed decoding. Email matching, verified-email
   admission, invitations, roles, sessions and audits remain application rules.

Protocol state can be restored into a new provider with identical configuration.
It is bound to issuer, client ID, redirect URL, selected authentication method,
endpoints, scopes and signing algorithms. Variable sections have separate counts
to prevent boundary collisions. Changed protocol configuration fails
closed. Application-specific provider versions and eligibility still need live
checks; the library does not inspect a database record or configuration revision.

`Assertion.Issuer` preserves the signed claim. `ProviderIssuer` is the trusted
discovery issuer. Both are exposed because go-oidc accepts Google's documented
legacy issuer form; the caller chooses and documents its canonical identity key.
`Claims` reads the signed payload without fetching userinfo or distributed claims.

## Network and credential handling

All requested endpoints must use HTTPS without URL credentials or fragments.
Issuer queries are refused. GET redirects are bounded and remain HTTPS; token
POST redirects are refused. Discovery, token and JWKS bodies default to 1 MiB and
each protocol operation defaults to ten seconds. Valid JSON followed by excess
whitespace is refused as oversized, not accepted as a truncated document.

The supplied transport owns DNS resolution, dial targets, private-host allowlists,
proxy policy and TLS trust. It must honor request cancellation and must not retry
token POST requests. A package-created transport has a 64 KiB response-header
limit; supplied transports should also use finite header limits. No TLS, issuer,
signature, audience or expiry skip option is exposed. An upstream insecure issuer
context cannot change discovery or signed-token trust.

Token authentication is explicitly selected from discovery and configuration:
`client_secret_basic`, `client_secret_post`, or `none` for an advertised public
client. Missing discovery methods default to Basic as specified by OIDC. The
OAuth library's trial authentication-style retry is never used. A lost or failed
token response does not cause another exchange. The caller must start a fresh
flow after an uncertain exchange, rather than reusing a consumed callback.

Provider/network errors are fixed sentinels; upstream response bodies and URLs
are not wrapped into them. Cancellation may additionally match the context error.
Configuration, state, authorization and provider debug formatting are redacted.
Default JSON excludes client secrets and protocol state. `CloseIdleConnections`
releases only a transport created internally; supplied transports remain owned
by their caller.

The TLS test IdP performs real authorization, token and JWKS requests with signed
RS256/ES256 JWTs. Tests cover PKCE, restored state, issuer compatibility, negative
token claims, oversized valid prefixes, TLS/timeouts, redirect/refused replay,
parallel flows and sensitive output. These are protocol tests, not production
provider certification, browser-bound persistence or application login acceptance.
