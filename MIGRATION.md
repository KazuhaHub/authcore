# Migrating to authcore

> `audit` was part of this guide and has been removed from authcore entirely.
> Two consumers measured it and it saved neither any code; the reasoning is in
> [ADR 2](docs/adr/0002-audit-is-not-shareable.md).

This document is for engineers on **Passwall-Sub-Panel (PSP)**,
**Report-Portal (RP)**, and **AlertHub (AH)** moving their own hand-rolled
SAML and passkey (WebAuthn) code onto
`github.com/KazuhaHub/authcore`'s `saml` and `passkey` packages.

It assumes you have already read each package's own doc comment
(`saml/provider.go`, `passkey/passkey.go`) — this document
is the delta between what you have today and what authcore gives you, not a
restatement of the API reference.

## Two behavioral rules that apply to every package here

These were established by `captcha` (already in production in all three
projects) and hold for `saml` and `passkey` too. If you have
already migrated to `captcha`, skip to [Per-package migration](#per-package-migration).

### 1. Configuration is fixed at construction time

`saml.New(cfg)`, `passkey.New(cfg)`, and a `Store`'s constructor all take
their `Config`/parameters once and never re-read them. There is no
`Reload(ctx, newConfig)` method anywhere in these packages, unlike:

- PSP's `SAMLService.Reload(ctx, cfg)` (`internal/service/auth/saml.go:199`),
  which rebuilds the whole `*saml.ServiceProvider` under a mutex so an admin
  can change SAML settings without a restart.
- PSP's `SAMLService.StartMetadataRefresh` background goroutine
  (`saml.go:216`), which periodically re-fetches and swaps in fresh IdP
  metadata.

**What this means for you:** if your deployment needs to change SAML/IdP
config, WebAuthn RP config, etc. at runtime, that reload loop stays entirely
in your own code — you construct a **new** `*saml.Provider` /
`*passkey.Service` from the new `Config` and atomically swap the pointer
your handlers read (e.g. behind an `atomic.Pointer[saml.Provider]`, exactly
the shape PSP's `s.mu`-guarded `s.sp` field already has — you're moving the
swap target, not inventing a new pattern). authcore does not build that
reload machinery for you, the same way `captcha.NewImageGenerator`'s
`Option`s are captured once and never revisited.

`geoip.Watcher` is the one exception in this module (it hot-reloads a
`.mmdb` file by design), and it is exactly that: an exception, not evidence
that other packages should have grown the same feature.

### 2. Nothing in this module logs

No package here imports `log`, `log/slog`, or any third-party logging
library, in `saml` or `passkey` (verified: `grep -rln '"log"\|log\.\|slog\.'`
across all six packages' non-test `.go` files returns nothing). Every
rejection is a distinguishable Go error (a sentinel like
`saml.ErrTooManyAssertions`, or a wrapped `%w` chain with enough context to
format a useful log line) — logging that error, at what level, with what
extra fields, is entirely your call.

This is a **behavior change**, not just an implementation detail, for code
that currently logs inside the "service" layer you are deleting:

```go
// PSP, internal/service/auth/saml.go:504 (today — deleted on migration)
assertion, err := sp.ParseResponse(r, possibleRequestIDs)
if err != nil {
	if ire, ok := err.(*saml.InvalidResponseError); ok {
		log.Warn("saml: parse response failed", "private_err", ire.PrivateErr)
	} else {
		log.Warn("saml: parse response failed", "err", err)
	}
	// ...
}
// ...
if s.assertionAlreadyConsumed(r.Context(), assertion.ID, exp, time.Now()) {
	log.Warn("saml: assertion replay detected", "assertion_id", assertion.ID)
	return nil, fmt.Errorf("SAML assertion already consumed")
}
```

```go
// After migration — the log call moves to YOUR handler, once, around the
// single authcore call, instead of being scattered through the validation
// pipeline (crewjam's own parse errors, the replay check, the multi-
// assertion check, etc. all surface through this one error return now):
assertion, err := provider.ValidateResponse(ctx, r, possibleRequestIDs)
if err != nil {
	log.Warn("saml: validation failed", "err", err) // your logger, your fields
	http.Error(w, "authentication failed", http.StatusForbidden)
	return
}
```


## Import aliases

Every `authcore/<pkg>` sub-package keeps the same base name as the
hand-rolled package it replaces, by design — that's what lets you swap the
import path without renaming every symbol at the call site. The one cost of
that design is that when your own module *also* has a package literally
named `<pkg>`, the two imports collide and the compiler forces you to give
one of them a local name.

### When you need an alias

You need an alias only when the **consumer file's own package name** is the
same as the authcore package you're importing into it. Nothing else
qualifies — not "this feels related to auth," not "I'd like it to stand out."

```go
// internal/geoip/reader.go
package geoip

import authcoregeoip "github.com/KazuhaHub/authcore/geoip" // collision: this
// file's package is also named geoip — alias required
```

```go
// internal/app/sso.go
package app

import "github.com/KazuhaHub/authcore/saml" // no collision: this file's
// package is "app", not "saml" — import unaliased, call it saml.Provider etc.
```

Do not alias an import just because a sibling file elsewhere in the same
project had to. Check the actual `package` clause of the file you're editing;
an unaliased `authcore/saml` import inside `package app` is correct and
should stay that way even though `authcore/geoip` needed `authcoregeoip` two
directories over.

### How to name the alias, when you need one

Use the `authcore` prefix on the colliding package's own name:
`authcoregeoip`, `authcorecaptcha`, `authcoresaml`, `authcorepasskey`. It's more typing than a short prefix or suffix, but it is
`grep`-able (`grep -rn authcorecaptcha` finds every call site unambiguously),
it never collides with anything else a consumer might name a local variable
or helper, and it makes "this identifier comes from the shared library, not
from this package's own code" visible at the call site without following the
import block. Use this exact convention consistently across PSP, RP, and AH
rather than each project (or each migration pass within a project)
inventing its own — RP's first two migrations already produced two
different conventions (`authgeoip` and `captchacore`) for the same problem
inside a single repository, which is the failure mode this section exists to
prevent for `saml` and `passkey`.

### This is a stopgap, not the target architecture

A wrapper package that exists only to re-export authcore types under a
consumer's pre-existing package path (RP's `internal/geoip`, for instance,
once it's down to forwarding declarations) is a transitional shape, not
where things should permanently live. It exists so a migration can land
without forcing every call site across the consumer's codebase to change its
import in the same commit. Once a given package's migration has been in
production for a consumer long enough to trust it, the better end state is
to delete that consumer's wrapper package entirely and have call sites
import `authcore/<pkg>` directly — at which point the alias question above
mostly disappears too, since there's no longer a same-named consumer package
for it to collide with. Don't let the wrapper package harden into permanent
architecture by default; if a migrated package's wrapper is still doing
nothing but forwarding a year on, that's worth an explicit follow-up ticket,
not silent acceptance.

## Per-package migration

### `saml`

#### What you implement

| Interface | Purpose | Your options |
|---|---|---|
| `saml.ReplayCache` | `SeenOrAdd(ctx, id string, expiresAt, now time.Time) (bool, error)` | `saml.NewMemoryReplayCache(capacity)` (bounded, TTL) for a single process, or your own backed by whatever store already holds `possibleRequestIDs`/session state |

Everything else (`Config`, `*Provider`, `Assertion`) is a value type or
opaque handle — nothing else to implement.

#### PSP → `saml`

PSP's `SAMLService` (`internal/service/auth/saml.go`, 636 lines) +
`assertionReplayCache` (`saml_replay.go`, 75 lines) collapse into one
`saml.Provider` plus your own thin HTTP handlers.

**Before** (`internal/service/auth/saml.go`):
```go
type SAMLService struct {
	mu     sync.RWMutex
	sp     *saml.ServiceProvider
	cfg    *config.SAMLConfig
	replay assertionReplayCache // in-process only; SetReplayStore(r) for durable
}

func (s *SAMLService) ParseACSResponse(r *http.Request, possibleRequestIDs []string) (*SAMLAssertion, error) {
	// ... 80 lines: ParseForm, whitespace-strip the base64 payload (Entra ID
	// line-wraps at 76 chars), sp.ParseResponse, status-code extraction on
	// failure, replay check with a hand-computed NotOnOrAfter+MaxClockSkew
	// expiry, then map crewjamsaml.Assertion fields into SAMLAssertion.
}
```

**After** (your handler, using `saml.Provider`):
```go
provider, err := saml.New(saml.Config{
	EntityID:    cfg.EntityID,
	ACSURL:      cfg.ACSURL,
	IDPMetadata: idpMetadata, // you still own fetch/refresh — see rule #1 above
	Key:         cfg.Key,
	Certificate: cfg.Certificate,
	// ReplayCache: nil uses a bounded saml.MemoryReplayCache; pass your own
	// SQL-backed ReplayCache for durability across restarts (this replaces
	// SetReplayStore(ports.SAMLReplayRepo)).
})

func (s *Server) samlACS(w http.ResponseWriter, r *http.Request) {
	assertion, err := provider.ValidateResponse(r.Context(), r, s.possibleRequestIDs(r))
	if err != nil {
		log.Warn("saml: validation failed", "err", err)
		http.Error(w, "authentication failed", http.StatusForbidden)
		return
	}
	// assertion.NameID / assertion.Attribute("...") replace SAMLAssertion's
	// Subject/Attributes fields — same information, neutral shape.
}
```

**What you keep doing yourself:** the Entra-ID base64 whitespace-stripping
workaround is *not* in `saml` — crewjam/saml v0.5.1 (pinned here) still uses
`base64.StdEncoding`, so if you still see wrapped payloads from an IdP,
strip them in your handler before calling `ValidateResponse`, exactly as
today. Mapping `Assertion.Attribute("...")` onto your `nameid`-vs-attribute
subject-source admin setting is also unchanged — that policy was never
`saml`'s to own.

**What you gain for free:** multi-assertion rejection, decompression-bomb
caps on the redirect binding, and weak-signature-algorithm rejection — none
of which PSP's `SAMLService` had.

#### RP → `saml`

RP's `Server.samlACS` (`internal/app/saml.go`) already has its own
`requireDestination` pre-check — the exact gap `RequireDestination` (on by
default in this package) closes:

**Before:**
```go
// crewjam skips the Destination check when the response is unsigned and the
// attribute is absent — see service_provider.go:1008. We don't accept that.
if err := requireDestination(raw, s.samlACSURL(slug)); err != nil {
	http.Error(w, "invalid SAML response", http.StatusBadRequest)
	return
}
a, err := sp.ParseResponse(r, s.possibleRequestIDs(slug))
```

**After:** delete `requireDestination` entirely — `saml.Config.RequireDestination`
defaults to `true`, so `provider.ValidateResponse` already enforces exactly
this, with the same semantics. RP's weak-signature-algorithm allowlist
(SHA-256+) similarly becomes the default (`RejectWeakSignatures`, on by
default) instead of RP's own pre-parse XML scan — delete that too. RP's
policy of refusing `EncryptedAssertion` outright is *also* the package
default (`AllowEncryptedAssertions: false`) — no change needed. RP's
duplicate-attribute-name rejection has no default equivalent (PSP/AH merge
silently); set `Config.StrictAttributes = true` to keep RP's stricter
behavior.

Because RP is multi-tenant (one `*saml.ServiceProvider` per `SSOProvider`
row), you'll construct one `saml.Provider` per tenant, same shape as today,
just built from `saml.Config` instead of `saml.ServiceProvider` fields
directly.

#### AH → `saml`

AH's `SAML.ParseResponse` (`internal/sso/saml.go:117`) calls
`s.sp.ParseResponse(r, nil)` — no replay protection, no `InResponseTo`
tracking at all (relies entirely on `AllowIDPInitiated`). Migrating to
`saml.Provider` is a pure hardening upgrade with nothing to preserve:

**Before:**
```go
func (s *SAML) ParseResponse(r *http.Request) (*Claims, error) {
	a, err := s.sp.ParseResponse(r, nil) // AllowIDPInitiated covers nil requestIDs
	// ...
}
```

**After:**
```go
assertion, err := provider.ValidateResponse(r.Context(), r, nil /* still IdP-initiated-only, if that's intentional */)
```

AH gains replay protection, multi-assertion defense, decompression-bomb
defense, weak-signature rejection, and Destination hardening — all net new.
If AH's IdP is Entra ID or another that emits a transient default NameID
format, also note `saml.Config.NameIDFormat` defaults to
`crewjamsaml.UnspecifiedNameIDFormat` (unlike letting crewjam's own
`transient` default through), which is the same fix PSP and RP already had
to make by hand.

### `passkey`

#### What you implement

| Interface | Purpose | Your options |
|---|---|---|
| `passkey.CredentialStore` | `FindByID`, `FindByUserHandle`, `Save`, `UpdateSignCount` | Your own SQL adapter — this is **required**, there is no usable default (`passkey.MemoryCredentialStore` is dev/test-only: it never evicts, since a credential is permanent data) |
| `passkey.SessionStore` | `Put`, `Take` (ceremony challenge state) | `passkey.NewMemoryStore(...)` / `passkey.DefaultMemoryStore()` (bounded, TTL) is fine for a single process; implement your own for a multi-instance deployment |

#### PSP → `passkey`

PSP's `Service` (`internal/service/passkey/passkey.go`, 461 lines) +
`session_store.go` (75 lines) map onto `passkey.Service` almost field-for-field,
with one behavior you must now do explicitly:

**Before** (`passkey.go:406`):
```go
func (s *Service) finalizeAssertion(ctx context.Context, stored *domain.PasskeyCredential, cred *webauthn.Credential) error {
	if cred.Authenticator.CloneWarning {
		return fmt.Errorf("%w: authenticator state regression (possible clone or replay)", domain.ErrUnauthorized)
	}
	// ... persist advanced sign count
}
```

That code refuses a flagged login *before* writing anything, and
`passkey.Service` does not do that on its own: it never rejects a login on
`CloneWarning`, and it calls `CredentialStore.UpdateSignCount` before either
Finish method returns. The equivalent is to refuse from inside the Store,
which is the only place a refusal can also prevent the write:

**After** — your `UpdateSignCount`:
```go
func (s *store) UpdateSignCount(ctx context.Context, credentialID []byte, cred webauthn.Credential, usedAt time.Time) error {
	if cred.Authenticator.CloneWarning {
		// Refusing here fails the ceremony with a nil *LoginResult, and the
		// record is untouched because nothing has been written yet.
		return fmt.Errorf("%w: authenticator state regression (possible clone or replay)", ErrRegression)
	}
	// ... persist the advanced sign count
	return nil
}
```

If your policy is instead "accept it, but raise an alert", inspect
`result.Credential.Authenticator.CloneWarning` on the returned `*LoginResult`.
That works too, but by then the advanced counter and flags have already been
written back — so a policy that must not write cannot be expressed that way.
See the `CredentialStore.UpdateSignCount` doc comment for the full contract.

PSP's own passwordless-vs-2FA `UserVerification` split
(`Config.UserVerification`, forced to `protocol.VerificationRequired` for
discoverable/passwordless ceremonies) maps directly onto
`passkey.Config.UserVerification` plus a per-call
`webauthn.WithUserVerification(protocol.VerificationRequired)` override —
see the `passkey` quickstart in the main README. PSP's `Rename`/`Delete`/`List`/
`CountByUsers`/`RevokeAll` (pure SQL against PSP's own
`webauthn_credential_repo.go`) stay in PSP's own repository code unchanged —
`passkey.CredentialStore` intentionally does not have equivalents (see its
doc comment).

#### RP → `passkey`

RP already builds a registration exclusion list to prevent duplicate
registration — this is now the package **default**
(`BeginRegistration` auto-excludes every credential already on file for
`handle`; pass your own `webauthn.WithExclusions(...)` in `opts` to
override). Delete RP's own exclusion-building code; nothing else changes,
including RP's `UserVerification: Preferred`-never-forced policy (it's still
the package default — RP doesn't need to change `Config.UserVerification`
at all).

#### AH → `passkey`

AH's `userHandle(id int64)` (8-byte big-endian) is exactly the kind of
opaque handle `passkey.Service` expects — no change needed there, just pass
`userHandle(userID)` as `handle` to every call. AH's own session map
(`putSession`/`takeSession`, `internal/passkey/passkey.go:86`) only sweeps
expired entries **on** `Put` — it has no hard capacity cap, so a sustained
flood of abandoned `BeginRegistration`/`BeginLogin` calls (never finished)
can grow it without bound between sweeps. `passkey.DefaultMemoryStore()` (or
your own `passkey.NewMemoryStore(maxItems, ttl)`) is capacity-bounded on top
of the TTL sweep — a real fix, not just a rename. AH also gains
multi-origin support (`Config.RPOrigins` is a list; AH's `rpOrigin` today is
a single string) and the exclusion-list behavior it never had.

## Verifying a migration

Once a project's code compiles against authcore, confirm nothing regressed
the same way this module's own CI does:

```sh
go build ./... && go vet ./... && gofmt -l .
go test ./... -race -count=1
```

If your project is one of the three this module's `saml`/`passkey`
tests were built against, the `security-test-suite` repository
(`kazuhahub-github/docs/security-test-suite`) can also be pointed at your
migrated endpoints — see that repository's README for its route-alignment
table — to confirm the specific attack classes (replay, decompression
bombs, counter rollback, chain tampering, etc.) are still rejected after
the migration, not just that the code compiles.
