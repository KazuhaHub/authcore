# FRICTION.md — geoip & captcha: the first real consumer

This is the friction report from migrating **Report-Portal (RP)**'s
`internal/geoip` and `internal/captcha` (+ `internal/app/captcha_api.go`'s
underlying implementation) onto `authcore/geoip` and `authcore/captcha`.

RP was chosen deliberately over AlertHub, which has never adopted authcore at
all: migrating a project with 172 test files and 73k lines of real, exercised
code proves the API design holds up, not just that it compiles. This document
is that proof's paper trail — every place the migration had to write glue, work
around a signature, or lean on a doc comment instead of the type system.

Work happened on two local branches (`refactor/authcore-geoip`,
`refactor/authcore-captcha`), merged into `refactor/authcore-batch1` in RP's
repo, on top of `go get github.com/KazuhaHub/authcore@main` (pseudo-version
`v0.0.0-20260917105012-fcd79922bfb2`, resolving to commit `fcd7992`; no tag
exists yet). Full verification (`go build ./...`, `go vet ./...`, `go test
./... -race -count=1` — all 172 test files, including `internal/app`'s) is
green on the merged branch. Nothing in RP's test suite was weakened to make
that happen — the only deleted tests are five `geoip` cases that tested
`mapRecord`, a decoding function that no longer exists in RP because it moved
into authcore; authcore's own `geoip_test.go`/`fixture_test.go` cover the same
ground with a strictly larger set of schema variants.

## Bottom line

**Yes, mostly.** Both packages' public surface mapped onto RP's pre-existing
contracts almost without friction — `geoip.Open`/`Reader`/`Location`/`DBInfo`
transplanted as straight type aliases and one-line forwards, and
`captcha.Store`'s method set is a deliberate, exact match for
`base64Captcha.Store`, so RP's own store-level test needed zero changes. The
two behavioral differences authcore's own `MIGRATION.md` already calls out
(construction-time-fixed `TokenVerifier`, no internal logging) were bridged
exactly as documented, with no surprises.

There is **one real, non-cosmetic defect** found in this pass:
`captcha.NewTokenVerifier`'s connection-reuse behavior is a footgun that the
type system does nothing to prevent and that `go doc` alone will not surface.
See **P0** below — this is the one item worth fixing, or at minimum
loud-documenting, before the first tag. Everything else is minor and can wait.

---

## P0 — none

The original draft of this report raised one, and it was wrong. It is kept here
rather than deleted, because a retracted finding is more useful to the next
reader than a silently shortened list.

### Retracted: "`NewTokenVerifier` drops connection reuse when `WithHTTPClient` is omitted"

The claim was that `NewTokenVerifier`, absent `WithHTTPClient`, builds a
brand-new `http.Client` *and transport* per call, so a caller following
`MIGRATION.md` rule #1 (configuration fixed at construction, therefore build
one per request when your config is live-reloadable) would pay a fresh TCP and
TLS handshake on every captcha verification.

`token.go` really does build `&http.Client{Timeout: cfg.timeout}` per call. But
a `http.Client` with a nil `Transport` does not get its own transport — it
falls back to `http.DefaultTransport`, a single package-level pool shared by
every such client. Building the client is cheap; building a `Transport` is what
is not, and this does not do that.

Measured, 2026-09-17, Go 1.26:

| 50 sequential requests | TCP connections opened |
|---|---|
| fresh `&http.Client{Timeout: …}` each time (nil Transport) | **1** |
| fresh `&http.Client{Transport: &http.Transport{}}` each time | **50** |

So per-call construction is fine, and the ~15 lines of glue RP added to hold a
shared `*http.Client` were not needed. They are harmless and can stay — an
explicit client is reasonable practice — but the reason recorded against them
was not real.

**What is worth documenting** is the inverse, which the retracted finding had
backwards: a caller who supplies `WithHTTPClient` with a client carrying its
*own* `&http.Transport{}`, and constructs per call, really will leak a
connection pool per verification. That is the 50-connection row above. A doc
comment on `NewTokenVerifier` now says so.

## P1 — worth doing before the next package migrates, not blocking

### Package-name collision between `authcore/geoip` and every consumer's own `geoip` package

Every migration of an `authcore/<pkg>` sub-package into a consumer that
already has its own same-named package (RP's `internal/geoip` importing
`authcore/geoip`, and this will repeat for `saml`, `passkey`, `audit`) forces
an import alias:

```go
import authgeoip "github.com/KazuhaHub/authcore/geoip"
```

Single-file cost is trivial, but it is a *predictable*, repeating cost across
every one of PSP/RP/AH's four remaining migrations (`saml`, `passkey`,
`audit`, and any future package), because the whole point of these adapter
packages is "keep the consumer's existing package path stable" — which
means the name collision is closer to guaranteed than coincidental.

**Suggested fix:** `MIGRATION.md` already has a "Per-package migration"
section for each package — add one line to its top-level guidance
recommending the `<pkg>core` alias convention (`geoipcore`, `samlcore`,
`passkeycore`, ...) so it is at least a consistent style across the three
consumer projects instead of each one inventing its own (RP's own commit
uses `authgeoip`/`captchacore` — two different conventions in the *same*
repository, from two different migration passes). This is a documentation
fix, not an API fix — package names cannot avoid this collision by
design (the mirrored path is a feature), so this is entirely about lowering
the cost consistently, not eliminating it.

### `captcha.Provider` and RP's four-way provider dispatch don't compose

`authcore/captcha.Provider` (three token-provider values) and RP's own
provider identifiers (`"image"`, `"turnstile"`, `"recaptcha"`, `"hcaptcha"`
— four values, because "image" is a business-layer concept authcore
correctly has no opinion on) are two unrelated string types that happen to
share three literal values. The bridge is a bare, compiler-unchecked cast:

```go
tv, err := captchacore.NewTokenVerifier(captchacore.Provider(provider), secret, opts...)
```

This is **not a defect** — image-vs-token is genuinely RP's business
decision to make, not authcore's, and baking a fourth "not really a token
provider" value into `captcha.Provider` would be the wrong fix. What's
missing is small: an exported `IsKnownProvider(string) bool` (or a
`ParseProvider(string) (Provider, bool)`) covering just the three token
providers, so a caller's own larger dispatch table can delegate the "is this
one of authcore's three" sub-check instead of re-deriving it by hand. Every
future consumer of `authcore/captcha` will re-derive this exact same
three-way check; it is currently a `switch` a caller has to write blind
because nothing exported states the closed set of valid `Provider` string
values (the three `Provider*` constants are enough for a human, not for a
`switch default:` a linter can check for exhaustiveness).

Severity: nice-to-have, cheap to add, doesn't need to happen before tagging.

---

## P2 — noted, no action needed

These were flagged during migration and are worth recording so they aren't
re-litigated by the next migrating engineer, but none of them call for an
authcore change.

- **`geoip.Reader.Lookup` returning `(Location, error)` where the error is
  reachable only via a corrupt/unreadable database file, never a miss.**
  Confirmed by reading `geoip/geoip.go:108-128`: the error is exactly and
  only `r.db.Lookup`'s own error (a truncated/corrupt `.mmdb`), never raised
  for "address not in database." RP's adapter discards it, which is
  zero-behavior-change versus RP's pre-migration code (which folded both
  cases into an empty `Location` already). Whether `Lookup` needs its own
  error at all, versus moving corruption detection to `Open()` time only
  (mmap'd files can still be truncated post-open on a hostile filesystem,
  which is presumably why the error exists at all) is a legitimate design
  question, but not one this migration surfaces new information about — it
  is usable exactly as designed, a caller just has to decide whether that
  rare case matters to them. No change requested.

- **`CountryCode` is now upper-cased (`strings.ToUpper`) where RP's
  pre-migration code passed the raw `.mmdb` value through unchanged.** Real,
  confirmed behavior difference (`geoip/geoip.go:165`), but it is a
  correctness improvement (ISO 3166-1 alpha-2 codes are canonically
  upper-case; a `.mmdb` that provided lower-case would previously have
  broken any caller comparing against the canonical form) and RP's full test
  suite is green with it in place, meaning no consumer of the pre-migration
  lower-case behavior existed. Deliberate, correct, not filed as an issue.

- **Double-validated "empty secret" error path in `captcha.Verify` →
  `verifyToken` → `NewTokenVerifier`.** RP's `Service.Verify` already
  rejects an empty secret to produce its own error string before calling
  `NewTokenVerifier`, so `NewTokenVerifier`'s identical check
  (`"captcha: token verifier requires a non-empty secret"`) can never fire
  through this call path. Harmless, self-inflicted by RP wanting its own
  error message; not something authcore should change.

- **The `NewTokenVerifier` default-endpoint-from-`Provider` lookup is dead
  code from RP's perspective**, because RP always calls `WithEndpoint`
  explicitly (it needs to redirect providers at an `httptest.Server` in
  tests, and has for as long as this code has existed, migration or not).
  This means the two-line "quickstart" shape of the API
  (`NewTokenVerifier(ProviderTurnstile, secret)`) doesn't actually apply to
  a caller with RP's requirements — not a defect, just a note that the
  convenient path and the tested-in-production path diverge for a caller
  that needs endpoint overrides for any reason (testing, self-hosted
  siteverify, enterprise tier).

---

## What confirms the design decisions that *did* pay off

Worth recording the wins as precisely as the friction, since "record only
complaints" would bias the next reader toward over-correcting:

- **`captcha.Store`'s method set was designed to be identical to
  `base64Captcha.Store`'s** (`Set`, `Get`, `Verify(id, answer, clear)`),
  stated explicitly in `store.go`'s own doc comment as deliberate. This
  meant RP's `internal/captcha/captcha_test.go`, which pokes the store
  directly (`s.store.Verify(ch.ID, guess, false)` as a brute-force helper),
  needed **zero changes** — the one place in this whole migration where an
  authcore type slotted into an existing test with no adaptation at all.
- **`geoip.Location` / `geoip.DBInfo` fields matched RP's pre-existing JSON
  shape exactly**, letting RP replace two struct declarations with two
  `type X = authcore.X` aliases rather than a translation layer — meaning
  RP's `audit.go` JSON output (an externally-observed API surface) is now
  guaranteed to never drift from authcore's definition, instead of two
  copies that could silently diverge.
- **The two documented behavioral rules (construction-fixed config,
  no internal logging) bridged cleanly** because `MIGRATION.md` states them
  as general package-family rules rather than leaving each migrating
  engineer to discover them independently per package. The pattern used
  here (build a fresh `TokenVerifier` per call from live config, driven off
  `Result` for logging) is now the reference example for `saml` and
  `passkey`'s equivalent construction-time-fixed configs.

## Glue-code accounting

| Package | Pre-migration | Post-migration | Genuinely new logic |
|---|---|---|---|
| `geoip` | 171 lines | 82 lines | ~0 — pure forwarding/aliasing; the package got smaller |
| `captcha` | 216 lines (`captcha.go` only) | 241 lines | ~95 lines: per-call `TokenVerifier` construction, the two reconstructed `log.Printf` lines, the explicit capacity/TTL/timeout constants and their "why this isn't the default" comments |

Of that ~95 lines in `captcha`, roughly 15 (the shared `s.http *http.Client`
field, its `New()` initialization, and the comment explaining why it exists)
are pure compensation for the **P0** footgun above — i.e., the only
*avoidable* glue in this migration, avoidable if authcore fixed or
prominently documented that gap. The rest (per-call construction, log-line
reconstruction) is inherent to the two behavior differences `MIGRATION.md`
itself declares as permanent package-family rules, not something a better
authcore API could remove — a caller that needs live config and its own
logging will always own that seam somewhere.

## Capability audit (pre- vs. post-migration, RP)

All confirmed by reading both implementations side by side, not merely by
running tests:

| Behavior | Pre-migration | Post-migration | Match |
|---|---|---|---|
| Image challenge single-use | `store.Verify(id, answer, true)` | `ImageGenerator.Verify` → `store.Verify(id, answer, true)` internally | identical |
| Image store capacity | `base64Captcha.GCLimitNumber` = 10240 | `imageStoreCapacity = 10240` passed explicitly to `NewMemoryStore` | identical (authcore's own default is 10,000 — RP overrides it) |
| Image store TTL | `5 * time.Minute` (hardcoded, not `base64Captcha.Expiration`'s 10 min default) | `imageStoreTTL = 5 * time.Minute` passed explicitly | identical |
| Digit driver visual params | `NewDriverDigit(80, 240, 5, 0.7, 80)` | authcore's zero-value default (`defaultDriverParams`) is byte-identical | identical, no override needed |
| Token hostname pinning | skip if `expectedHost==""` OR provider `Hostname==""` | skip if `expectedHost==""` (no `WithAllowedHostnames` call) OR provider `Hostname==""` (authcore's own internal check) | identical |
| Config hot-reload (secret/provider/host change takes effect without restart) | `Settings` passed fresh on every `Verify` call | fresh `TokenVerifier` built from live `Settings` on every `verifyToken` call | identical |
| Operator-visible logs on rejection | `log.Printf` for error-codes and hostname mismatch | same two `log.Printf` call sites, reconstructed from `Result` | identical (confirmed firing in test output, not just compiling) |
| geoip lookup miss / private / unmapped address | empty `Location`, no error | empty `Location`, no error (error discarded is same-outcome, see P2) | identical |
| geoip `Open`/`Info`/`Close`/nil-Reader safety | present | present, forwarded 1:1 | identical |

**No capability loss identified in either package.**

## Verification performed for this report

- `git log`/`git diff --stat` against `main` for both source branches, to
  confirm the claimed file-change scope (only `internal/geoip/*`,
  `internal/captcha/captcha.go`, `go.mod`, `go.sum` — `internal/app/*` is
  untouched byte-for-byte).
- Read `authcore/geoip/geoip.go` and `authcore/captcha/{captcha,store,token}.go`
  in full against RP's adapters and RP's pre-migration originals
  (`git show main:...`), line by line, for every claim in this document.
- Merged both branches into `refactor/authcore-batch1` (resolved one
  `go.sum` conflict by taking the union of both sides' checksum lines, then
  `go mod tidy`; `go.mod` merged cleanly).
- `go build ./...`, `go vet ./...`, `gofmt -l .` — all clean on the merged
  branch.
- `go test ./... -race -count=1` — **all packages pass**, including
  `internal/app` (the 149s package covering SAML/audit/geo-update/webhook
  integration tests) and both migrated packages.
- Local toolchain is `go1.26.3` at `/opt/homebrew/bin/go`, but `go.mod`
  declares `go 1.26.6` with no `toolchain` line, so `GOTOOLCHAIN=auto`
  (the default, left unset) transparently downloads and runs the matching
  `go1.26.6` toolchain from the module cache — no manual workaround needed,
  and this matched both prior migration passes' experience once the correct
  toolchain was cached.
