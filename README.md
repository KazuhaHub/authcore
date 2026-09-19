# authcore

> **Status: pre-v1.** This module has no tagged release yet. Package APIs may
> still change without notice between commits; pin to a specific commit SHA
> (not a branch) if you depend on it before v1.0.0 is tagged.

`authcore` is a small set of independent, infrastructure-level Go packages
extracted from three separate services that had each reimplemented the same
things: rate limiting, captcha issuance, IP-to-location lookup, and — as of
`saml` and `passkey` — SAML/WebAuthn ceremony orchestration and
activity logging.

## Design principle: share mechanism, not policy

Every package here implements a **mechanism** — a generic, reusable piece of
plumbing — and deliberately knows nothing about **policy**: no accounts, no
users, no tenants, no organizations, no roles, no permissions. None of that
vocabulary appears anywhere in these packages' public APIs, and it never will
by design.

Concretely, this means:

- **No domain types.** You will not find a `User`, `Account`, `Tenant`,
  `Org`, or `Role` type in this module, and none should ever be added.
- **Callers identify themselves opaquely.** Where a package needs to tell
  "who" apart — a captcha challenge id, a client address — it accepts a
  caller-supplied opaque `string` or a narrow interface the caller
  implements, and never interprets what that string means. Whether such a
  string represents a client IP, an API token, or a hash of a tenant ID is
  entirely the caller's business.
- **No web-framework coupling.** Public signatures use only `net/http`
  types (`http.Handler`, `*http.Request`, ...). None of gin, echo, or any
  other framework's types appear in this module's API, so any of these
  packages works the same under any of them. A caller on a framework with
  its own middleware shape (e.g. gin's `gin.HandlerFunc`) writes a small
  adapter in their own code; that adapter is intentionally not part of this
  module.
- **Packages don't depend on each other.** `captcha`, `geoip`, `saml`, and
  `passkey` are independent leaves. None imports another package in this
  module. Pull in exactly the ones you need.

### Why there is no `identity` or `authflow` package

Session management, login flows, password/OTP verification, token issuance,
and anything else that has to reason about "who is this and what are they
allowed to do" is **policy**, not mechanism — it is inseparable from an
application's account model, which is exactly what this module refuses to
know about. Bundling that here would either force every caller into one
opinionated identity model, or quietly reintroduce the account/tenant
vocabulary this module exists to keep out. That kind of package belongs in
each application (or in a separate, explicitly opinionated module upstream of
it), built on top of these mechanism packages — not inside `authcore`.

This holds even for `saml` and `passkey`, which sit closer to
"identity" than `captcha`/`geoip` do but keep to the same rule.
Each is an **orchestration layer over a protocol library**
(`crewjam/saml`, `go-webauthn/webauthn`) — never an account model:

- `saml` turns a validated SAML Response into a neutral `Assertion` (NameID,
  attributes, session index). It never decides what a NameID or attribute
  means for your account model.
- `passkey` runs a WebAuthn ceremony against an opaque, caller-supplied
  **user handle** — a byte string it round-trips and never interprets — not
  a `User` type.

None of the three know what a NameID, a user handle, or an actor ID mean
beyond byte equality; mapping any of them onto an account is left entirely
to the caller, exactly like every other package in this module.

## Scope

authcore is identity protocol orchestration, plus the controls that protect
authentication flows.

Every package here answers one question: *does it protect an authentication
flow?* `saml` and `passkey` are the flows. `captcha` keeps login and
registration from being abused. `geoip` answers where a login came from.

Passing that test is necessary, not sufficient. `audit` passed it and was
removed anyway, because two real consumers measured it and it saved nobody any
code — see [ADR 2](docs/adr/0002-audit-is-not-shareable.md). `ratelimit`
passed it too and was removed for a different reason: nothing ever consumed it,
and the half of it worth sharing turned out to be client-IP resolution rather
than the limiter — see [ADR 3](docs/adr/0003-ratelimit-and-clientip.md).

A package that cannot answer that question belongs somewhere else, however
security-adjacent it looks. The name is deliberately narrow: a library with one
maintainer fills up with "well, it's security-related" unless something makes a
bad addition feel awkward, and a precise name is the cheapest thing that does.

Risk-control primitives — impossible travel, concurrent-session counting,
device fingerprinting — are expected to grow into a separate module rather than
land here. See [ADR 1](docs/adr/0001-scope-of-authcore.md) for the reasoning,
including why the module was not renamed or split, and what would trigger a
split later.

## Packages

| Package | Purpose | Built on |
|---|---|---|
| [`captcha`](./captcha) | Self-hosted image captcha: issue a challenge, verify a single-use answer | [`mojocn/base64Captcha`](https://github.com/mojocn/base64Captcha) |
| [`geoip`](./geoip) | Offline IP-to-location lookup against a local MaxMind-format (`.mmdb`) database, with optional hot-reload | [`oschwald/maxminddb-golang`](https://github.com/oschwald/maxminddb-golang) |
| [`saml`](./saml) | SAML 2.0 Service Provider orchestration: AuthnRequest issuance, SP metadata, Response/Assertion validation with replay, multi-assertion, decompression-bomb and weak-signature defenses `crewjam/saml` leaves to the caller | [`crewjam/saml`](https://github.com/crewjam/saml) |
| [`passkey`](./passkey) | WebAuthn ceremony orchestration: registration, allow-listed login, and discoverable (usernameless) login, keyed by an opaque user handle | [`go-webauthn/webauthn`](https://github.com/go-webauthn/webauthn) |

Each package has its own doc comment with the full design rationale; the
table above is just a map to find the right one.

## Installation

```sh
go get github.com/KazuhaHub/authcore/captcha
go get github.com/KazuhaHub/authcore/geoip
go get github.com/KazuhaHub/authcore/saml
go get github.com/KazuhaHub/authcore/passkey
```

Each package is imported and versioned independently (they're leaves in one
Go module), but since the module itself is pre-v1, all packages currently
move together on the same module version.

### Versioning policy

- **Before v1.0.0** (current state): no compatibility promise. Pin a commit
  SHA via `go get github.com/KazuhaHub/authcore/<pkg>@<sha>` for anything
  beyond experimentation.
- **From v1.0.0 on**: standard [Go module semantic versioning](https://go.dev/doc/modules/version-numbers).
  A breaking change to any package's public API bumps the module's major
  version (`v2`, `v3`, ...) per Go's module rules, even if only one package
  changed — because all three currently ship from one `go.mod`.

## Quickstart

### `captcha`

```go
package main

import (
	"fmt"

	"github.com/KazuhaHub/authcore/captcha"
)

func main() {
	// A nil store defaults to an in-process, TTL- and capacity-bounded
	// captcha.DefaultMemoryStore(); pass your own Store for a shared,
	// multi-instance deployment.
	gen := captcha.NewImageGenerator(nil)

	challenge, err := gen.Generate()
	if err != nil {
		panic(err)
	}
	// challenge.ID goes to the client alongside challenge.Image
	// (a data:image/...;base64,... URL ready for an <img src>).
	fmt.Println(challenge.ID)

	// Later, on the answer submission:
	ok := gen.Verify(challenge.ID, "12345")
	fmt.Println("correct:", ok) // Verify is single-use: a repeat call is always false.
}
```

### `geoip`

```go
package main

import (
	"fmt"

	"github.com/KazuhaHub/authcore/geoip"
)

func main() {
	reader, err := geoip.Open("/path/to/GeoLite2-City.mmdb")
	if err != nil {
		panic(err)
	}
	defer reader.Close()

	loc, err := reader.Lookup("203.0.113.1") // RFC 5737 documentation address
	if err != nil {
		panic(err) // the database itself couldn't be read
	}
	if loc.Empty() {
		fmt.Println("no location data for this address")
	} else {
		fmt.Println(loc.Country, loc.City)
	}
}
```

For a database that gets replaced on disk while the process runs (e.g. an
admin uploading a fresh `.mmdb`), use `geoip.Watcher` instead of a bare
`Reader` — it hot-reloads on file change and is nil-safe and error-free at
every call site:

```go
w := geoip.NewWatcher(geoip.WithPath("/path/to/GeoLite2-City.mmdb"))
defer w.Close()

loc := w.Lookup("203.0.113.1") // never errors; empty Location on any failure
```

### `saml`

```go
package main

import (
	"context"
	"fmt"
	"net/http"

	crewjamsaml "github.com/crewjam/saml"

	"github.com/KazuhaHub/authcore/saml"
)

// fetchIDPMetadata fetches and parses the IdP's metadata XML however your
// deployment keeps it current (a periodic fetch, a static file, ...).
// This package only consumes the parsed result.
func fetchIDPMetadata() *crewjamsaml.EntityDescriptor {
	return &crewjamsaml.EntityDescriptor{EntityID: "https://idp.example.com/saml/metadata"}
}

// possibleRequestIDsFor looks up which AuthnRequest.ID values are still
// outstanding for this browser (e.g. from a cookie-bound server-side
// store). Leave it empty to only accept IdP-initiated flows (with
// Config.AllowIDPInitiated set).
func possibleRequestIDsFor(r *http.Request) []string {
	return nil
}

func main() {
	provider, err := saml.New(saml.Config{
		EntityID:    "https://sp.example.com/saml/metadata",
		ACSURL:      "https://sp.example.com/saml/acs",
		IDPMetadata: fetchIDPMetadata(),
		// ReplayCache defaults to a bounded saml.MemoryReplayCache when nil.
	})
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/saml/login", func(w http.ResponseWriter, r *http.Request) {
		req, err := provider.NewAuthnRequest(r.URL.Query().Get("relay"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Persist req.ID so it can be returned from possibleRequestIDsFor later.
		http.Redirect(w, r, req.RedirectURL, http.StatusFound)
	})

	http.HandleFunc("/saml/acs", func(w http.ResponseWriter, r *http.Request) {
		assertion, err := provider.ValidateResponse(context.Background(), r, possibleRequestIDsFor(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		// Map assertion.NameID / assertion.Attribute("...") onto your own
		// account model here — this package never does that mapping for you.
		fmt.Fprintf(w, "authenticated: %s", assertion.NameID)
	})

	http.ListenAndServe(":8080", nil)
}
```

`Provider.ValidateResponse` closes gaps `crewjam/saml` leaves open by
design: assertion replay (via `ReplayCache`), a Response smuggling more than
one `Assertion`/`EncryptedAssertion`, a DEFLATE decompression bomb on the
redirect binding, an absent `Destination`, and SHA-1 signature algorithms —
see the package doc for exactly what each `Config` flag controls.

### `passkey`

```go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/KazuhaHub/authcore/passkey"
)

func main() {
	svc, err := passkey.New(passkey.Config{
		RPID:          "example.com",
		RPDisplayName: "Example Co",
		RPOrigins:     []string{"https://example.com"},
		// Credentials is the only required field with no in-memory default;
		// a real deployment backs it with its own SQL table.
		Credentials: passkey.NewMemoryCredentialStore(),
		// Sessions defaults to a bounded passkey.DefaultMemoryStore() when nil.
	})
	if err != nil {
		panic(err)
	}

	// handleFor resolves the opaque WebAuthn user handle for the caller's
	// own already-authenticated account — this package never derives it.
	handleFor := func(r *http.Request) []byte { return []byte("account-42") }

	http.HandleFunc("/passkeys/register/begin", func(w http.ResponseWriter, r *http.Request) {
		creation, sessionID, err := svc.BeginRegistration(r.Context(), handleFor(r), "alice", "Alice")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Persist sessionID (e.g. in a short-lived cookie) and send creation
		// to the browser's navigator.credentials.create().
		w.Header().Set("X-Passkey-Session", sessionID)
		json.NewEncoder(w).Encode(creation)
	})

	http.HandleFunc("/passkeys/register/finish", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.Header.Get("X-Passkey-Session")
		if _, err := svc.FinishRegistration(r.Context(), handleFor(r), sessionID, r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// A "passkey proper" (usernameless) sign-in flow:
	http.HandleFunc("/passkeys/login/begin", func(w http.ResponseWriter, r *http.Request) {
		// Unlike a second factor behind a password, a discoverable login is
		// the only factor, so it should require user verification explicitly.
		assertion, sessionID, err := svc.BeginDiscoverableLogin(r.Context(),
			webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Passkey-Session", sessionID)
		json.NewEncoder(w).Encode(assertion)
	})

	http.HandleFunc("/passkeys/login/finish", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.Header.Get("X-Passkey-Session")
		result, err := svc.FinishDiscoverableLogin(r.Context(), sessionID, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if result.Credential.Authenticator.CloneWarning {
			// Decide what a possible cloned credential means for your own
			// account model — this package only surfaces the signal. Note the
			// counter has already been written back by this point; to reject a
			// flagged login WITHOUT writing it, refuse inside your
			// CredentialStore.UpdateSignCount instead.
		}
		fmt.Fprintf(w, "signed in as handle %q", result.UserHandle)
	})

	http.ListenAndServe(":8080", nil)
}
```

`passkey.NewMemoryCredentialStore` is for development/tests only (it never
evicts — a credential is permanent data, not a cache entry); implement
`passkey.CredentialStore` against your own table for production. See the
package doc for why `protocol.VerificationPreferred` (the default) is *not*
enforced server-side, and why that matters specifically for a discoverable
login.

## Dependency policy

authcore is the single place where security-sensitive identity dependencies are
pinned for every service that consumes it. A stale pin here silently becomes a
stale pin in every downstream project, so version currency is a correctness
concern, not housekeeping.

- **Security-sensitive libraries are pinned to the latest release** and are
  updated in their own pull request, never batched with unrelated bumps. This
  currently covers:
  - `github.com/crewjam/saml` **v0.5.1** — SAML orchestration (`saml`)
  - `github.com/russellhaering/goxmldsig` **v1.4.0** — XML digital signature
    verification, a `crewjam/saml` dependency (`saml`)
  - `github.com/go-webauthn/webauthn` **v0.18.1** — WebAuthn ceremony
    library (`passkey`)
  - `github.com/coreos/go-oidc/v3` — reserved for the forthcoming `oidc`
    package; not yet a dependency of this module.

  `github.com/descope/virtualwebauthn` is pinned the same way but is a
  **test-only** dependency of `passkey` (a real virtual authenticator used
  to exercise genuine WebAuthn ceremonies in tests) — it never ships in a
  binary that imports this module.
- **Dependabot runs weekly** for both Go modules and GitHub Actions; see
  `.github/dependabot.yml`. Minor and patch bumps of non-identity libraries are
  grouped to keep review noise down.
- **GitHub Actions are pinned to a commit SHA** with the tag in a trailing
  comment, so a moved tag cannot change what CI executes.
- `govulncheck` runs on every push and pull request.

### Known follow-up

`geoip` uses `github.com/oschwald/maxminddb-golang` **v1**, which is the version
the consuming projects already use, so migrating to authcore does not force an
API change on them. A v2 line exists and is carried transitively by the test
fixture writer. Moving `geoip` to v2 is a deliberate future change, not an
oversight: it should happen once the consuming projects are ready to move with
it. v1 currently carries no published security advisories.


## Contributing

This module was extracted from production code in three separate services;
changes should keep serving all of their use cases (see each package's doc
comment for the specific reconciliation history) without reintroducing any
policy concept into the shared API. Before sending a change:

- `go build ./... && go vet ./... && gofmt -l .` must be clean.
- `go test ./... -race -count=1` must pass. Every package must keep test
  coverage for its exported behavior — do not merge untested new surface
  area.
- Test fixtures use only reserved documentation addresses (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`) and `example.com`; never a real IP,
  domain, or credential.
- If a change adds a dependency, prefer an established library over a new
  hand-rolled implementation, consistent with how each package already
  favors `httprate`, `base64Captcha`, `maxminddb-golang`, `crewjam/saml`,
  and `go-webauthn/webauthn` over reimplementing their algorithms.

## License

Apache License 2.0 — see [LICENSE](./LICENSE). Third-party components bundled
via this module's dependencies are listed with their licenses in
[NOTICE](./NOTICE).
