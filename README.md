# authcore

> **Status: pre-v1.** This module has no tagged release yet. Package APIs may
> still change without notice between commits; pin to a specific commit SHA
> (not a branch) if you depend on it before v1.0.0 is tagged.

`authcore` is a small set of independent, infrastructure-level Go packages
extracted from three separate services that had each reimplemented the same
things: rate limiting, captcha issuance, and IP-to-location lookup.

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
  "who" apart — a rate-limit bucket, a captcha challenge id — it accepts a
  caller-supplied opaque `string` or a narrow interface the caller
  implements, and never interprets what that string means. `ratelimit`'s
  `KeyFunc`, for example, returns a plain string; whether that string
  represents a client IP, an API token, or a hash of a tenant ID is entirely
  the caller's business.
- **No web-framework coupling.** Public signatures use only `net/http`
  types (`http.Handler`, `*http.Request`, ...). None of gin, echo, or any
  other framework's types appear in this module's API, so any of these
  packages works the same under any of them. A caller on a framework with
  its own middleware shape (e.g. gin's `gin.HandlerFunc`) writes a small
  adapter in their own code; that adapter is intentionally not part of this
  module.
- **Packages don't depend on each other.** `captcha`, `geoip`, and
  `ratelimit` are independent leaves. None imports another package in this
  module. Pull in exactly the ones you need.

### Why there is no `identity` or `authflow` package

Session management, login flows, password/OTP/passkey verification, token
issuance, and anything else that has to reason about "who is this and what
are they allowed to do" is **policy**, not mechanism — it is inseparable from
an application's account model, which is exactly what this module refuses to
know about. Bundling that here would either force every caller into one
opinionated identity model, or quietly reintroduce the account/tenant
vocabulary this module exists to keep out. That kind of package belongs in
each application (or in a separate, explicitly opinionated module upstream of
it), built on top of these mechanism packages — not inside `authcore`.

## Packages

| Package | Purpose | Built on |
|---|---|---|
| [`ratelimit`](./ratelimit) | `net/http` rate-limiting middleware, keyed by an opaque string (default: trusted-proxy-aware client IP) | [`go-chi/httprate`](https://github.com/go-chi/httprate), [`go-chi/chi/v5/middleware`](https://github.com/go-chi/chi) |
| [`captcha`](./captcha) | Self-hosted image captcha: issue a challenge, verify a single-use answer | [`mojocn/base64Captcha`](https://github.com/mojocn/base64Captcha) |
| [`geoip`](./geoip) | Offline IP-to-location lookup against a local MaxMind-format (`.mmdb`) database, with optional hot-reload | [`oschwald/maxminddb-golang`](https://github.com/oschwald/maxminddb-golang) |

Each package has its own doc comment with the full design rationale; the
table above is just a map to find the right one.

## Installation

```sh
go get github.com/KazuhaHub/authcore/ratelimit
go get github.com/KazuhaHub/authcore/captcha
go get github.com/KazuhaHub/authcore/geoip
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

### `ratelimit`

```go
package main

import (
	"net/http"
	"time"

	"github.com/KazuhaHub/authcore/ratelimit"
)

func main() {
	limiter := ratelimit.New(ratelimit.Config{
		Limit:  100,
		Window: time.Minute,
		// No proxy in front of this server: the zero-value TrustedProxies
		// reads RemoteAddr only and ignores any X-Forwarded-For header.
		// Behind a reverse proxy, declare the trust boundary explicitly:
		// TrustedProxies: ratelimit.TrustedProxies{Hops: 1},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	http.ListenAndServe(":8080", limiter.Middleware(mux))
}
```

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


## Dependency policy

authcore is the single place where security-sensitive identity dependencies are
pinned for every service that consumes it. A stale pin here silently becomes a
stale pin in every downstream project, so version currency is a correctness
concern, not housekeeping.

- **Security-sensitive libraries are pinned to the latest release** and are
  updated in their own pull request, never batched with unrelated bumps. This
  currently covers `github.com/crewjam/saml`, `github.com/go-webauthn/webauthn`,
  `github.com/coreos/go-oidc/v3` and `github.com/russellhaering/goxmldsig`
  (the latter three arrive with the `saml`, `passkey` and `oidc` packages).
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
  favors `httprate`, `base64Captcha`, and `maxminddb-golang` over
  reimplementing their algorithms.

## License

Apache License 2.0 — see [LICENSE](./LICENSE). Third-party components bundled
via this module's dependencies are listed with their licenses in
[NOTICE](./NOTICE).
