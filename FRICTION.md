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

**Status: resolved.** See `MIGRATION.md`'s "Import aliases" section, which
now states the rule (alias only on an actual collision with the consumer
file's own package name) and the convention (`authcore`-prefixed alias,
e.g. `authcoregeoip`/`authcorecaptcha` — not the `<pkg>core` suffix this
report originally floated below). The original finding is kept as-is below
for the record of how it was discovered.

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

---

## audit — Report-Portal

Second real consumer, on branch `refactor/authcore-audit` in RP's repo
(commit `9c8f1c7c`, on top of `main`@`3f39fa19`; not pushed). Scope: swap the
internals of `internal/app/audit.go`'s existing recorder methods
(`WriteAudit`/`recordChange`/`recordAuth`/`recordReportRead`/`recordV1Read`/
`ListAudit`/`DeleteAuditBefore`/`CountAuditBefore`/`AuditActions`/
`apiAdminAudit`) for `authcore/audit`, without touching any of the 76+4
call sites that use them or the 4 pre-existing audit test files.

### A note on method

The geoip/captcha report above retracted its own P0 after the fact. Every
finding below was independently reproduced before being written down, not
inferred from reading code or from the migrating engineer's own report:
`git diff --stat`/`--name-only` against `main` was run directly (not just
trusted) to confirm the claimed "only two files changed" scope; `go doc -all
./audit` was read fresh rather than recalled; every one of the ~74
`recordChange`/`recordAuth` call sites was grepped and eyeballed for a value
`json.Marshal` could fail on; and the two claims below that touch hash-chain
behavior were each backed by a disposable reproduction test, run once, and
deleted — not committed, not part of the migration, existing only to turn
"should behave this way" into "did behave this way, observed."

### Bottom line

**Yes, but with real growth, not shrinkage, and one genuine P1 worth fixing
before the next consumer wires up a `Chain`.** The facade
(`internal/app/audit.go`'s public/exported-within-package surface) is
provably untouched — every recorder method's signature, behavior, and error
semantics are byte-identical to `main`, confirmed by diff, not by reading the
migration's own summary of the diff. What changed is confined to the file's
internals: `auditJSON` now forwards to `audit.Marshal`, and two new methods
(`Append`/`Query`) make `*Store` satisfy `audit.Store` for a future consumer,
without production code calling either. No capability was lost.

## P0 — none

## P1 — worth doing before the next consumer chains a Store

### `Store.Append` can silently discard a `Chain`'s `Hash`/`PrevHash` with no error, and nothing in `audit`'s docs says a persistent adapter must guard against this

Reproduced directly (test written, run, and deleted — not part of the
migration): wrap RP's `*Store` in `audit.NewChain`, `Append` an event through
the chain. The in-memory `Event` the caller holds afterward has a correct,
non-empty `Hash` — `Chain.Append` did its job. But `*Store.Append`'s `INSERT`
statement (`internal/app/audit.go`, the new `Append` method) has no
`prev_hash`/`hash` columns to write into, because `audit_log` has none. It
does not error — `Store`'s contract has no requirement that it must persist
every field of `e`, and `audit.Store`'s doc explicitly says computing
`PrevHash`/`Hash` is "Chain's job, not the Store's," which a reader can
mistake for "the Store need not care about them at all." Reading the row back
through `Store.Query` returns `Hash=""`, `PrevHash=""` — not because nothing
was chained, but because the chain data was accepted and thrown away.

The practical consequence: a future engineer who adds `prev_hash`/`hash`
columns *conceptually* (i.e., decides "we're turning on chaining now") but
forgets to also update the adapter's `INSERT`/`SELECT` column lists gets no
compile error, no runtime error, and a `Chain.Append` that reports success on
every call. The first `Verify` then reports **every single event as broken**,
not just the pre-chain legacy rows the package doc's anchor section warns
about — a strictly worse and more confusing failure than the documented one,
because nothing about it looks like the documented pre-chain-history case
(the very first `Verify`able event *also* fails, immediately, so scoping the
range with `AfterSeq` — the anchor section's own fix for legacy history —
does not help; it was tried, and reproduced failing, in the same throwaway
test).

**Suggested fix**: add one sentence to `Store`'s interface doc (or `Chain`'s):
a persistent `Store` implementation that a caller intends to wrap in a
`Chain` MUST have storage for, and must persist, `e.Hash` and `e.PrevHash` as
given — `Chain` does not verify this and cannot detect it, because from
`Chain`'s side `Append` returning `nil` looks identical whether the wrapped
`Store` kept the hash or quietly dropped it. This is not a defect in the
shipped `MemoryStore` (it holds the whole `*Event` in memory, so this class
of bug cannot occur there), which is exactly why it would be easy for the
next SQL-backed consumer to assume Chain "just works" against any `Store` — it
does not, against one written without a `Chain` in mind from the start.

RP itself is **not** exposed to this today: nothing in `internal/app` calls
`audit.NewChain`, `Store.Append`, or `audit.Verify` in production (confirmed
by `grep -rn 'audit.Chain\|audit.NewChain\|audit.Verify' internal/`, zero
hits outside a comment), and the migration correctly did not add
`prev_hash`/`hash` columns to `audit_log`. This finding is about what a
*future* migration into a chained state would hit, not about anything wrong
with what shipped now.

## P2 — noted, no action needed

- **`ActorOU` has no home in `audit.Event`, by design, and stays a direct
  `INSERT` in `WriteAudit`.** `MIGRATION.md`'s "RP -> audit" section already
  names this as policy `audit.Event` refuses to carry. Confirmed the
  migration honored it correctly, not just claimed to: `WriteAudit` was left
  untouched (0 diff lines), and `TestAuditRecordsWhoDidWhatToWhich` — which
  asserts an `ActorOU` value deliberately unrelated to the actor's real group,
  specifically to catch a future "helpfully" recomputed `ActorOU` — passes
  unmodified. The new `Store.Append` adapter (the one path that *does* go
  through `audit.Event`) has no field to carry a caller-chosen `ActorOU` and
  falls back to the actor's *current* group instead; this is called out in
  that method's own doc comment, and nothing in production calls it, so it is
  a documented gap in an unused adapter, not a live behavior change.

- **`Event.Time` has no way to carry RP's two pre-existing on-disk timestamp
  formats (RFC3339 vs. pre-v0.4.15 local wall clock).** Also named in
  `MIGRATION.md`. Confirmed `auditBefore`, `likeT`, `ListAudit`'s two-part
  `ORDER BY`, and `DeleteAuditBefore`/`CountAuditBefore` are all 0-diff
  against `main` — the dual-format handling stayed entirely in RP's own code,
  exactly as the migration report claims. The new `Query` adapter has to
  guess a timezone for legacy rows (`parseAuditAt`, documented as "a
  documented guess, not a fact") because `Event.Time` is strongly typed and
  has nowhere to preserve "this row's zone was never recorded" — an
  inherent, not fixable, consequence of the type, and again confined to code
  no production path calls.

- **`audit.Filter` has no free-text substring field**, so RP's `Q` parameter
  (used by `TestAuditSearchesTheDetail`) has no equivalent and stays entirely
  in `ListAudit`, which the migration left untouched. `MIGRATION.md` already
  calls this a storage-engine concern deliberately kept out of `Filter`; the
  new `Query` adapter simply has no `Q` support, and nothing in RP calls it
  expecting one.

- **`Reader.Query`'s mandated ascending-`Seq` order is the opposite of what
  every audit console wants (newest first).** Deliberate — `Filter.AfterSeq`'s
  doc explains this is what makes a durable resumable cursor possible — but
  it means the new `Query` adapter is unusable as-is for RP's own
  `apiAdminAudit` handler, which correctly keeps calling `ListAudit` (its own
  independent, newest-first, dual-format-aware `ORDER BY`) instead. `Query`
  exists to satisfy the interface for a hypothetical future consumer, not
  because RP's console can use it.

- **`Marshal(nil)` behaves differently for an untyped `nil` literal
  (`""`) versus a `nil` value already boxed into a concrete type such as
  `map[string]any` (`"null"`).** Reproduced directly:
  `audit.Marshal(nil)` → `""`, `audit.Marshal(map[string]any(nil))` →
  `"null"`. This is standard Go interface-nil behavior, not an `audit`
  defect, and it is harmless here specifically because every one of RP's
  ~74 call sites passes `auditJSON`/the `detail` parameter as a typed
  `map[string]any` (including the literal `nil` passed at several call
  sites, which the Go compiler boxes into a typed nil map at the call
  site's parameter type) — so the observed output is `"null"` both before
  and after this migration, confirmed by reading every call site rather than
  assuming the type-safety argument holds. Worth a caller-side note for
  whoever migrates `saml`/`passkey`/AlertHub's audit usage next, since a
  caller that ever passes a bare untyped `nil` through an `any`-typed
  boundary would see `""` instead and silently lose the payload — nothing in
  RP does this today.

## What confirms the design decisions that did pay off

- **Keeping `WriteAudit`/`ListAudit` as direct SQL rather than routing them
  through the new `Store`/`Reader` adapter was the right call, not merely
  the cautious one.** The two behaviors that adapter cannot preserve
  (caller-supplied `ActorOU`, dual timestamp formats) are exactly the two
  `MIGRATION.md` already flags as things `audit.Event` will never carry —
  this migration is a real demonstration that the documented gap is not
  theoretical.
- **`audit.Marshal` slotted into `auditJSON` with zero output difference**
  for every real call site, confirmed by reading each one (all pass
  `map[string]any` built from strings/bools/numbers/slices, none of which
  `json.Marshal` can fail on) rather than by argument alone.
- **Adding the `Store`/`Reader` adapter as a pure addition — new methods
  nothing calls yet — kept the entire migration to a 2-file diff** (`git
  diff main...refactor/authcore-audit --stat`: `audit.go` and one new test
  file, nothing else) against a subsystem where the "real" data model
  (schema, dual timestamps, substring search, two other files' raw SQL
  reads of the same table) is too entangled with RP-specific guarantees to
  actually move. Confirmed the two raw-SQL readers of `audit_log` outside
  this package (`batch_store.go`'s `JobSurfaces`, `cleanup_store.go`'s
  usage stats) are 0-diff and therefore still work against the same table
  name/columns.

## Glue-code accounting

| Package | Pre-migration | Post-migration | Genuinely new logic |
|---|---|---|---|
| `audit` | 545 lines | 740 lines | ~180 lines: the `Store`/`Reader` SQL adapter (`Append`, `Query`, `parseAuditAt`, `auditSinceUntilClause`) that no production call site uses yet, plus doc comments explaining why `WriteAudit`/`ListAudit` deliberately do NOT route through it |

Unlike `geoip` (171 → 82 lines), `audit` **grew**. Recording this plainly
rather than searching for a way to present it as a win: under the ground
rules `MIGRATION.md` itself sets for this package (no `ActorOU`, no dual
timestamps, no substring search in `Filter`), there was no version of this
migration that could shrink RP's `audit.go` — the parts authcore actually
owns (`Event`'s core fields, `Marshal`) were already thin wrappers
(`auditJSON`) before this migration touched them. The 180 lines of new
adapter code buy RP nothing it uses today; they exist to hand a generic
`audit.Store`/`audit.Reader` to something outside this package later.

## Capability audit (pre- vs. post-migration, RP audit)

All confirmed by reading `git diff main...refactor/authcore-audit` directly,
not by trusting the migration's own summary of it:

| Behavior | Pre-migration | Post-migration | Match |
|---|---|---|---|
| `WriteAudit` — signature, direct-insert behavior, `ActorOU`/`At` passthrough | direct `INSERT`, no recompute | identical, 0 diff lines | identical |
| `recordChange`/`recordAuth`/`recordReportRead`/`recordV1Read` — signatures & bodies | — | 0 diff lines in every file containing them | identical |
| `ListAudit`/`DeleteAuditBefore`/`CountAuditBefore`/`AuditActions` — query logic, dual-format handling | — | 0 diff lines | identical |
| `apiAdminAudit` — response JSON shape | `items/total/actions/ou_names/timezone/geo/proxy_hint` | 0 diff lines | identical |
| `auditJSON` — output bytes for every real call site | hand-rolled `json.Marshal` | `audit.Marshal` wrapper | identical (verified per call site, see P2) |
| Hash-chain state | none (no columns, no chain code) | none (no columns, no chain code; `Append`/`Query` exist but nothing calls them) | identical — confirmed not half-enabled, see below |
| `batch_store.go`'s `JobSurfaces` raw SQL against `audit_log` | works | 0 diff, unaffected | identical |
| `cleanup_store.go`'s usage-stats raw SQL against `audit_log` | works | 0 diff, unaffected | identical |

**No capability loss identified.**

## Hash-chain / anchor semantics — verified, not assumed

Confirmed by direct inspection, not by trusting the migration's claim:
`grep -rn 'audit.Chain\|audit.NewChain\|audit.Verify\|prev_hash\|PrevHash' internal/`
returns exactly one hit, a comment; `audit_log`'s schema
(`internal/app/store.go`) has no `prev_hash`/`hash` columns. The chain is
genuinely **off**, not half-on — there is no state where old rows silently
have `prev_hash=NULL` while new ones don't, because nothing writes either
column at all.

Two disposable reproduction tests (written, run, deleted — not committed)
confirmed the reasoning behind that decision is sound rather than assumed:

1. **The documented anchor trap is real.** Chaining a few new events on top
   of pre-existing `WriteAudit` rows and calling `audit.Verify(ctx, st,
   Filter{...}, "")` (genesis anchor, no scoping) does report the first
   legacy row as broken (`Reason: "hash does not match the event's own
   content"`) — exactly the false positive `Verify`'s doc comment warns
   about, not evidence of tampering.
2. **Scoping the range does not fix it here, for the different reason in
   the P1 above.** Retrying with `Filter{AfterSeq: <last legacy Seq>}` and
   `anchor=""` — the documented fix for case 1 — still fails, but now on
   the *first chained* event, because `*Store.Append` never persisted that
   event's `Hash`/`PrevHash` in the first place (no columns for them). This
   is what turned "the anchor parameter has a rough edge" into a concrete,
   verified P1 rather than a hypothetical one.

## Verification performed for this report

- `git diff main...refactor/authcore-audit --stat` and `--name-only`, run
  directly: exactly `internal/app/audit.go` and one new test file changed;
  nothing else in `internal/app` (including the 4 pre-existing audit test
  files, `store.go`'s schema, `batch_store.go`, `cleanup_store.go`,
  `cleanup_api.go`) has any diff.
- Read the full `git diff main...refactor/authcore-audit -- internal/app/audit.go`
  line by line against `go doc -all ./audit` (read fresh, not recalled)
  for every claim above.
- Grepped and read all ~74 `recordChange`/`recordAuth` call sites and the
  handful of direct `auditJSON`/`WriteAudit` call sites for any value
  `json.Marshal` could fail on (NaN/Inf floats, channels, funcs, cycles) —
  none found; every detail map is built from strings, bools, numbers, and
  slices of same.
- `GOWORK=off go build ./...`, `go vet ./...`, `gofmt -l .`, and
  `go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./internal/app/...` —
  all clean.
- `GOWORK=off go test ./... -race -count=1 -timeout=15m` — **all packages
  pass**, `internal/app` in 209.5s.
- All 31 audit-related tests (27 in the 4 pre-existing files, unmodified;
  4 new in `audit_authcore_test.go`) run individually by name and confirmed
  passing, not just swept up in a package-level "ok".
- Wrote, ran, and deleted two throwaway reproduction tests (not committed,
  not part of the migration) to turn the two hash-chain claims above from
  "should be true" into "observed true": the anchor trap on unscoped
  `Verify`, and the `Hash`/`PrevHash` silent-drop through
  `Store.Append` that defeats the documented `AfterSeq` scoping fix.
- Confirmed the branch is local-only: `git rev-parse --abbrev-ref
  --symbolic-full-name @{u}` reports no upstream, and `git log
  origin/main..refactor/authcore-audit` shows exactly the one migration
  commit. Nothing was pushed.

---

## audit — the keep-or-drop measurement

Third data point, and the one this whole exercise was designed around:
AlertHub is the one real consumer that actually uses a hash chain in
production, with `VerifyAuditChain` exposed over the API and an external
SIEM collector independently re-verifying the same hashes. If `audit`'s
`Chain` was ever going to earn its place, this was the test.

It didn't get to run. `AlertHub`'s `canonicalAudit` hashes `org_id` as part
of every entry — a real security property (moving a row to a different org
breaks the chain, not just editing its content) — and `authcore/audit`'s
`Event`/`canonicalBytes` have no field for a tenant/org id and, by explicit
package doc, never will ("this package has no notion of accounts, users,
tenants, organizations, or roles, and none should ever be added to it").
`canonicalBytes` is also private and unexported, so there is no hook to add
one from the consuming side either. That's not an adapter-writing problem;
it's a structural mismatch between what AlertHub's chain protects and what
authcore's chain is capable of protecting, and no amount of glue code on
AlertHub's side fixes it.

**I did not take this on faith from the migration report — I reproduced it
myself.** I copied AlertHub's real `canonicalAudit`/`auditHash` (verbatim,
from `server/internal/store/audit.go`) and used it to hash a 3-row chain the
way AlertHub's DB already would. I then translated those same rows
field-for-field into `authcore/audit.Event` — dropping only `OrgID`, since
there is nowhere for it to go — keeping the already-computed `Hash`/`PrevHash`
exactly as persisted, and ran them through `audit.Verify(ctx, store,
Filter{}, "")` from an unmodified checkout of `authcore` at current `main`.
Result:

```
audit.Verify(anchor=""): OK=false Count=1 BadSeq=1
Reason="hash does not match the event's own content (the event was edited,
        or it was never chained — see Verify's doc comment)"
```

It fails on the very first historical row, every time, for every existing
chain AlertHub has ever written — not because anything was tampered with,
but because `authcore`'s hash function is simply a different function.
Swapping AlertHub onto `authcore/audit.Chain` would not just fail to add
value; it would make `VerifyAuditChain` report AlertHub's entire existing
audit history as corrupted, and would require AlertHub to keep its own
`canonicalAudit`/verify logic running forever just to check pre-cutover rows
— meaning **nothing shared code was supposed to replace could ever actually
be deleted**. (The reproduction was a throwaway Go module built outside this
repo, using an unmodified checkout of `authcore` via a `replace` directive;
it is not committed anywhere and this repo's own files were untouched by it.)

### The four data points

| Consumer | Uses the hash chain? | Lines before | Lines after | Δ | Notes |
|---|---|---|---|---|---|
| `geoip` @ RP | n/a | 171 | 82 | **−89** | Clean win — pure forwarding, no local features lost |
| `captcha` @ RP | n/a | 216 | 241 | +25 | Acceptable — cost is two permanent, documented behavior differences (live-config `TokenVerifier`, caller-owned logging), not authcore friction |
| `audit` @ Report-Portal | No (chain never wired up) | 545 | 740 | **+195** | Paid for `Event`/`Marshal`/an unused `Chain`; still had to hand-roll everything the shared model omits (`ActorOU`, dual timestamps, `Q` search) |
| `audit` @ AlertHub | **Yes, in production, seriously** | 468 | 468 | **0 — migration never attempted** | Blocked before writing a single adapter line: `Chain` cannot cover `org_id`, and the incompatibility is confirmed by an independent, self-run test (above), not by reading the report |

Only `geoip` shrank. `captcha` grew acceptably for reasons unrelated to
authcore's design. `audit` has now been tried by both a non-chain consumer
(net +195 lines, dependency without benefit) and the one real chain consumer
(net 0, because the migration is structurally blocked) — two real attempts,
zero times the package's headline feature actually helped anyone.

### Verdict: **drop `audit` from authcore. Do not merge either migration branch.**

This is not close, and it is not a matter of one unlucky consumer. Read
against what was actually measured:

- The package's only real differentiator over "each project writes its own
  `INSERT`" is `Chain`/`Verify`. The one production consumer serious enough
  to have built `VerifyAuditChain`, anchor-aware pruning, and an external
  SIEM cross-check around a hash chain **cannot use authcore's**, because
  `canonicalBytes` cannot cover a caller field that consumer's security
  model depends on, and the package's own doc forbids adding one. This
  isn't a gap that a smarter `audit.Store` adapter closes — it is a design
  decision in `authcore/audit` itself (no tenant concept, ever) directly
  colliding with what a real deployment needed hashed.
- The consumer that *did* complete a migration (RP) grew by 195 lines and
  left `Chain` unused — so even the "favorable" data point never actually
  tested the chain; it just paid `Event`/`Marshal` overhead for a model it
  didn't need reshaping into.
- Net effect across every real audit migration attempted so far: **0 lines
  removed, 195 lines added, one migration blocked outright.** `geoip`'s
  −89 lines is a real, unrelated win for a different package — it is not
  evidence that sharing works for `audit`, and I'm not letting it average
  out the audit numbers to make the total look better.

**If someone wants to argue for keeping `audit` anyway**, the honest framing
of RP's 195 lines is: that is not "onboarding cost that will amortize as
more consumers join" — there is no visible mechanism by which it gets
cheaper, because the one axis that would make `audit` worth the dependency
(the chain) is the axis that just failed its only real test. Call the 195
lines what they are: a net cost paid for `Event`/`Marshal` plumbing RP could
have written in fewer lines itself, in exchange for a `Chain` field it
doesn't use.

### What to do with what already exists

- **`authcore/audit/*`** (`audit.go`, `chain.go`, `memstore.go` and tests):
  remove from `authcore`. Leaving it in place unused invites a third
  consumer to repeat this exact investigation from zero. If the intent is
  to revisit this later, the actionable prerequisite is specific and should
  be written down wherever this decision is recorded: `canonicalBytes`
  would need to accept caller-supplied extra fields (e.g. a generic
  `Extra map[string]string` folded into the hash) *before* asking a second
  real hash-chain consumer to try again — not a bigger adapter on the
  consumer's side.
- **Report-Portal's `refactor/authcore-audit` branch** (commit `9c8f1c7c`,
  local-only, not pushed): do not merge. `geoip`/`captcha` are unaffected —
  they were already merged to RP's `main` separately, in PR #6
  (`a82e054b`), before the audit branch existed. This branch's only content
  is the `audit` migration this report is rejecting.
- **AlertHub's `refactor/authcore-audit` branch** (local-only, not pushed):
  contains exactly one commit, `f9ba3bd` — the `go.mod` module-path fix
  (`github.com/kazuha/alerthub` → `github.com/KazuhaHub/AlertHub`). No audit
  migration code was ever written on this branch; it was correctly stopped
  before starting once the blocker above was confirmed. The module-path fix
  is a genuine, unrelated bug (`go get` fails against the repo's real
  location today) and is worth keeping regardless of the audit verdict —
  recommend landing that one commit through AlertHub's normal path,
  separately from any audit decision.
- **`fix/chain-detects-dropped-hashes`** (already merged to `authcore`
  `main`): harmless either way; only relevant if `audit/` stays.

### Still kazuha's call

- Actually delete `authcore/audit/*`, or leave it in the tree marked
  deprecated/experimental with this report linked from its doc comment?
- Delete RP's `refactor/authcore-audit` branch, or leave it unmerged as a
  documented dead end?
- Land AlertHub's `f9ba3bd` go.mod fix on its own (small, uncontroversial,
  independent of this verdict) — separate PR, this report doesn't do it?
- Is a `canonicalBytes` redesign (caller-extensible hash fields) worth
  pursuing before proposing `audit` to a third consumer, or is the package
  fully off the table?

## passkey — Report-Portal

Third real consumer, on local branch `refactor/authcore-passkey` in RP's
repo (not pushed, nothing committed — all changes sit in the working tree on
top of `main`@`4789d0f9`), on `go get github.com/KazuhaHub/authcore@main`
pinned to commit `2137c0fdf84c` (the commit immediately after `audit` was
removed, confirmed via `git log --oneline --all | grep 2137c0f` in this
repo). Scope: swap the internals of `internal/app/passkey.go`'s WebAuthn
ceremony orchestration (register/login begin-finish, challenge parking,
counter write-back) for `authcore/passkey`, without touching any of the ~18
symbols (4 HTTP handlers, 5 `*Store` methods, 6 internal helpers directly
called by `passkey_test.go`, plus the `webauthn_credentials` schema) that
sit outside that one file.

### A note on method

This report is written by a different party than the migration it reviews
(a verification pass, not the implementer's own writeup), following the same
rule the `audit` review adopted after the geoip/captcha report's P0 had to be
retracted: every claim below was reproduced directly, not accepted from the
migration's own summary. Concretely — `git diff main --stat` against the
actual (uncommitted) working tree, not the branch-to-branch diff the task
instructions suggested first (that diff is empty; nothing on this branch has
been committed, confirmed with `git log main..refactor/authcore-passkey`);
`git show main:internal/app/passkey.go` read and diffed line-by-line against
the working copy, not sampled; `authcore/passkey`'s five source files
(`passkey.go`, `registration.go`, `authentication.go`, `credential_store.go`,
`session_store.go`) read in full rather than taken from its package doc
comment alone; the go-webauthn v0.17.4→v0.18.1 struct diff re-run directly
(`diff` on both module versions' `credential.go` in the local module cache)
rather than trusted from the migration's claim that only `Extensions` was
added; three new tests written independently of the migration's own test
file, exercising real cryptographic ceremonies via
`github.com/descope/virtualwebauthn` (not mocked); and the full suite
(`go build`, `go vet`, `gofmt -l`, `go test ./... -race -count=1`) run twice
from a clean invocation, not reused from the migration's own log.

One claim in the migration's own writeup did not survive this process intact
— see P1 #3 below, which corrects rather than merely repeats it. That is the
point of doing this independently: the geoip/captcha report's retracted P0
was a warning that a migration's self-report can be wrong in a way that
still reads as careful, not just in a way that is obviously sloppy.

### Bottom line

**Yes, keep it — but this is the `captcha` outcome (real growth, real
value), not the `geoip` outcome (a clean line-count win), and the migration's
own report already said so plainly rather than rounding up.** The facade
(`internal/app/passkey.go`'s four HTTP handlers, five `*Store` methods, and
every symbol `passkey_test.go` calls directly) is provably untouched —
confirmed by diff, not by reading the migration's summary of the diff — and
all 13 pre-existing passkey tests plus the migration's own 4 new ones plus
this report's 3 independent new ones (20 total) pass, including under
`-race`. No capability was lost. `internal/app/passkey.go` grew from 373 to
554 lines (+181, confirmed by direct `wc -l` on both revisions), which is a
real cost, honestly reported by the migration rather than obscured — see
Glue-code accounting below for what that growth actually buys.

### P0 — none (verified, not assumed)

The candidate this report actually checked and rejected: "the go-webauthn
v0.17.4→v0.18.1 struct diff might have changed more than `Extensions`,
silently invalidating stored credentials." Rerun directly against both
module versions' `credential.go` in the local module cache (not trusted from
the migration's claim) — confirmed: `Extensions CredentialExtensions
'json:"extensions,omitzero"'` is the only field added; every other field
(`ID`, `PublicKey`, `AttestationType`, `AttestationFormat`, `Transport`,
`Flags`, `Authenticator`, `Attestation`) is byte-identical between versions,
and `authenticator.go` (holding `SignCount`/`CloneWarning`) was untouched
entirely. This report's own `TestVerifierLegacyCredentialJSONAuthenticates`
independently confirms it by reconstructing a v0.17.4-shaped JSON from an
explicit field allow-list (not by deleting a key from a v0.18.1 record, which
the migration's own test does and which is a weaker check — see P2 #6) and
logging in against it successfully. No P0 survives.

### P1 — worth doing before the next consumer wires up a ceremony-scoped SessionStore

#### `CredentialStore.Save` has no channel for caller-owned metadata, and the only one Go's type system leaves (`context.Value`) is a code smell every such caller has to independently discover and accept

Confirmed by reading `credential_store.go` directly: `Save(ctx,
cred StoredCredential) error`, and `StoredCredential` is exactly
`{UserHandle []byte, Credential webauthn.Credential}` — there is no third
field, and the package doc is explicit this is deliberate ("Credential
*management*... deliberately not part of this package's API"). That
deliberateness is real and correctly scoped — a passkey's display label is
account-model data, not WebAuthn-ceremony data, and this package is right
not to know about it. But "deliberate" and "friction-free" are different
claims: RP's only two options were (a) a second `UPDATE` after `Save`
returns, reopening exactly the kind of read-after-write window this
migration's own report flagged as unacceptable, or (b) thread the label
through `ctx` with a private key type (`passkeyLabelKey{}`), which is what
RP did. Every future caller with the same shape of problem (any policy data
that must land in the same row as the credential, atomically) reinvents this
same choice from scratch, because nothing in the package doc suggests the
`context.Value` pattern as the sanctioned answer — it just happens to be the
only channel `Save`'s signature leaves open. A one-paragraph note on
`CredentialStore.Save`'s doc comment naming this as the expected pattern
(or, alternatively, accepting free-form `map[string]any` metadata that this
package stores opaquely and returns unmodified) would turn a "figure it out"
into a "here's how."

#### `Begin*`/`Finish*` wrap a caller's own `CredentialStore`/`SessionStore` failure in the same generic `fmt.Errorf` shape as everything else, with no sentinel a caller can positively match to tell "our own storage broke" (500) from "the ceremony was rejected" (400/401)

Confirmed by reading `registration.go`/`authentication.go` directly: every
store-originated error is `fmt.Errorf("passkey: <verb>ing <noun>: %w", err)`
— textually distinguishable by a human reading the message, but not by
`errors.As`/`errors.Is` against anything this package exports. go-webauthn's
own errors ARE returned unwrapped (the package doc says so, and this was
verified rather than assumed: `s.wa.FinishRegistration`/`FinishLogin`
results flow straight through with no wrapping), so a caller COULD in
principle treat "is a `protocol.Error`" as the positive signal and
everything else as "must be our store" — but that is reasoning by exclusion,
not a supported contract, and it silently misclassifies any future error
this package might start returning for a reason that is neither (a config
error from a bad `Now`, for instance). RP's chosen fix —
wrapping every `CredentialStore` method's own error in an unexported
`*passkeyStoreError` at the RP-side adapter boundary and unwrapping with
`errors.As` in the handler — is correct and entirely on RP's side of the
interface, which is the right place for it to live if this package doesn't
want to commit to a sentinel. But every caller needing this same
distinction (which is most of them — a 500-vs-4xx split is not an unusual
thing to want) reinvents the same wrapper. A single exported
`ErrCredentialStore`/`ErrSessionStore` sentinel this package wraps its own
`fmt.Errorf`s in (in addition to, not instead of, the descriptive message)
would let every caller use one `errors.Is` check instead of building their
own wrapper type.

#### `SessionStore` has no concept of "ceremony kind" — real, but the consequence the migration's own report drew from it ("must build a Service per kind") does not hold, and is corrected here, not merely repeated

Confirmed by reading `session_store.go` directly: `Put(ctx, data)
(id, err)` / `Take(ctx, id) (data, ok)` — no kind parameter anywhere in the
interface, so nothing stops a challenge issued by `BeginRegistration` from
being handed to `FinishLogin` at the `SessionStore` layer specifically (in
practice go-webauthn's own request-shape parsing — an attestation response
does not parse as an assertion response — makes this an unlikely real
exploit path, but the `SessionStore` layer itself provides no defense of its
own, and a caller's own adapter has to be the one providing it, exactly as
`ceremonySessionStore.kind` does here).

Where the migration's own report overstates the consequence: it frames
building a `ceremonySessionStore` (and therefore a `passkey.Service`) per
ceremony kind as something authcore's API forces. It does not. `Put`/`Take`
both receive `ctx` (confirmed: `registration.go`/`authentication.go` thread
it from `BeginRegistration(ctx, ...)`/`FinishRegistration(ctx, ...)` etc.
straight to `s.sessions.Put(ctx, ...)`/`s.sessions.Take(ctx, ...)`), and this
same migration already establishes the pattern of carrying caller-owned
policy data through `ctx` for exactly this kind of gap (see P1 #1's label
key). A single `SessionStore` implementation that read an expected "kind"
value off `ctx` (set once per call site, `BeginRegistration` vs
`BeginLogin`) would let ONE shared `passkey.Service` serve both ceremony
types, with no loss of the cross-kind protection `ceremonySessionStore.kind`
provides today. RP's two-`Service`-per-request design is not wrong, and it
was independently necessary anyway for the hot-reloadable-RP-ID reason in P2
below — but it is a design choice RP made, not one `SessionStore`'s shape
required. `SessionStore` genuinely has no native "kind" concept; that part
of the finding stands. What does not stand is treating "no native kind
concept" and "must instantiate multiple Services" as the same fact.

### P2 — noted, no action needed

#### The package doc's "a typical deployment constructs one Service at startup and shares it" guidance has no caveat for a Relying Party config that can legitimately change without a restart

`passkey.go`'s package doc states the startup-once pattern as the norm with
no qualification. It is a reasonable default, but it is silently
incompatible with any deployment where the RP ID/origin is admin-configured
and expected to take effect on the next request (RP's own pre-existing
requirement, unrelated to this migration — see `TestPasskeyRelyingPartyComesFromPublicURL`,
untouched by this migration). The escape hatch — rebuild `Service` per
request — is safe only when `SessionStore` itself holds no state tied to
the `Service` instance (a database-backed store, not `DefaultMemoryStore()`),
and that precondition is not mentioned anywhere the "typical deployment"
guidance appears. Not a defect — nothing forces the startup-once pattern —
but a caller who takes the doc's own "typical" framing at face value and
later needs config hot-reload will not discover the incompatibility until a
production incident (every Begin/Finish pair silently fails because the
Finish request almost never lands on the same freshly-built `Service`
instance). This report's own
`TestVerifierPasskeyServiceRejectsUnconfiguredPublicURL` confirms RP's
mitigation (rebuild per request, backed by the `auth_requests` table) works
correctly, but the underlying incompatibility this works around is still
worth one sentence in the package doc.

#### `CredentialStore.UpdateSignCount`'s unconditional-write-back-even-on-`CloneWarning` behavior — the migration's own report undersells how well this is actually documented

The migration's writeup describes this as relying "entirely on注释兜底"
(entirely on a doc comment as a backstop) with "没有任何结构性提示" (no
structural indication) for future maintainers. Read directly,
`credential_store.go`'s doc comment on `UpdateSignCount` is not a passing
mention — it is a dedicated paragraph stating explicitly that this method
"is called after every cryptographically successful login, including one
where `cred.Authenticator.CloneWarning` is set," that the write-back is
"unconditional," and that deciding what a clone warning MEANS "is the
caller's policy." That is about as strong a structural signal as a doc
comment can give without the type system enforcing it — this is closer to
"thoroughly documented, deliberately left to the caller" than to "silently
relying on a comment nobody will read." Recorded here as a correction to the
migration's own framing, not as an independent finding: the underlying fact
(no `Config` flag exists to suppress the write-back; a caller wanting RP's
policy must implement it in their own `CredentialStore.UpdateSignCount`, as
RP did) is accurate and is not a defect — it is exactly the "mechanism, not
policy" split this package commits to everywhere else, applied consistently
here too.

#### The migration's compatibility test strips an `"extensions"` key that its own comment admits was never present in the sample it tested

`TestPasskeyPreMigrationCredentialJSONStillAuthenticates` (the migration's
own test) registers a real credential, then does
`delete(asMap, "extensions")` before rewriting the stored row — but its own
`t.Log` in the same test observes this is a no-op, because `omitzero` means
a credential with no extension outputs never serializes an `"extensions"`
key in the first place. The test still passes and still proves something
real (a stored credential authenticates after the migration), but it does
not, by itself, prove the specific claim it is named for — that a genuinely
v0.17.4-shaped record (which structurally COULD NOT have carried that key,
rather than happening not to) round-trips. This report's own
`TestVerifierLegacyCredentialJSONAuthenticates` closes that gap by
reconstructing the JSON from an explicit v0.17.4 field allow-list instead of
deleting a key from a live v0.18.1 record. Not a P1: the migration's test is
honest about its own limitation in its own log output, which is exactly the
right thing to do with a test that turns out weaker than intended — it is
recorded here as a completeness note, not a defect.

### What confirms the design decisions that did pay off

- **Errors from go-webauthn itself really do pass through unwrapped.**
  Verified by reading `registration.go`/`authentication.go`: every
  `s.wa.Finish*` result is returned directly, with no `fmt.Errorf` wrapper —
  only this package's OWN store-originated errors get wrapped (see P1 #2).
  A caller that wants `protocol.Error` detail on a genuine ceremony failure
  gets it without this package getting in the way.
- **`CloneWarning` surfaced, not decided.** Verified end-to-end with a real
  forged-clone signature (`TestPasskeyCloneWarningRejectsAndDoesNotAdvanceCounter`,
  reproduced independently in spirit by this report's own passing run of
  that same test under `-race`): RP's pre-migration policy — reject the
  login AND do not advance the stored counter baseline — survived the
  migration completely intact, implemented entirely in RP's own
  `CredentialStore.UpdateSignCount`, with zero changes to `authcore/passkey`
  itself. This is the migration's cleanest evidence that "mechanism, not
  policy" works as designed under a real, security-relevant policy
  divergence.
- **`ctx` really does flow end-to-end**, confirmed directly in source (not
  assumed from the doc): every `Begin*`/`Finish*` call threads its `ctx`
  argument to both `CredentialStore` and `SessionStore` calls, which is what
  makes both the label-via-context pattern (P1 #1) and the
  kind-via-context alternative this report identifies (P1 #3) possible at
  all — a `Service` that dropped `ctx` internally would foreclose both.

### Glue-code accounting

| | Lines |
|---|---|
| `internal/app/passkey.go`, pre-migration (`main`) | 373 |
| `internal/app/passkey.go`, post-migration | 554 |
| Net change | **+181** |
| — of which: retained solely for `passkey_test.go` to call directly, no longer reachable from any production handler (`passkeyUser` type+methods, `webAuthn()`, `s.passkeyUser()`, `takeCeremony()`, `credentialDescriptors()`) | ~56 |
| — of which: exists only to satisfy `CredentialStore.FindByID`'s unconditional interface requirement; no handler on RP's own path calls it (RP does not offer discoverable login) | ~28 |
| — of which: genuinely new, genuinely load-bearing production glue (two adapters, `passkeyService()`, error-wrapping type, label-context key, rewritten handler bodies, and the comments explaining each divergence from pre-migration behavior) | ~97 |

Unlike `geoip` (171→82, a clean win) and more like `captcha` (216→241,
+25), this is real growth. Unlike `audit` (545→740, +195, eventually
rejected), the growth here is not owed to a shared type that turned out
data-layer-incompatible with a second consumer — the ~84 lines that are not
"genuinely load-bearing" above are retained for test-reachability and
interface-completeness, both individually justified (see Bottom line), not
dead weight nobody accounts for. Whether ~97 lines of new glue, in exchange
for deleting the hand-rolled Begin/Finish orchestration, the exclusion-list
construction, and the ceremony single-use bookkeeping this package now
owns, is worth it is a judgment call — this report's position is that it is
(see Bottom line), but it is not a line-count win and should never be
described as one.

### Capability audit (pre- vs. post-migration, RP passkey)

All confirmed by reading `git diff main -- internal/app/passkey.go`
directly, not by trusting the migration's own summary of it:

| Behavior | Pre-migration | Post-migration | Match |
|---|---|---|---|
| RP ID / origin derivation, refuses when `public_url` unset | `webAuthn()`, per-request | `passkeyService()`, per-request (P2 #4 discusses why per-request is required) | identical, confirmed by this report's own new test |
| Registration exclusion list (no duplicate re-registration) | hand-built via `credentialDescriptors()` | built internally by `authcore/passkey.BeginRegistration` from `FindByUserHandle` | identical outcome, ownership moved into authcore |
| Ceremony challenge storage | `auth_requests` table, `stashCeremony`/`takeCeremonyAny` | same table, same functions, now called from `ceremonySessionStore` | identical, byte-for-byte reused |
| Ceremony TTL | 5 minutes (`passkeyChallengeTTL`) | unchanged, same constant | identical |
| Ceremony single-use (webauthn session token) | `ConsumeAuthRequest`, atomic | unchanged | identical |
| Cross-user ceremony claim rejected | hand-checked (`takeCeremony`'s `wantUser`) | go-webauthn's own internal handle-vs-session.UserID check (see P1 #3's `ctx` discussion for why RP's hand-check is now redundant on the production path, though still tested directly) | identical outcome, enforcement moved into go-webauthn |
| Counter-rollback (clone) detection: reject login | yes | yes | identical, confirmed under `-race` |
| Counter-rollback: do NOT advance stored counter baseline on a rejected clone signal | yes (`return` before `TouchPasskey`) | yes (`CredentialStore.UpdateSignCount` short-circuits on `CloneWarning`) | identical, this report's own independent test passes |
| WebAuthn user handle = username | yes (`passkeyUser.WebAuthnID()`) | yes (`[]byte(cred.UserHandle)`, `[]byte(user)` at every call site) | identical, existing credentials' handle semantics unchanged |
| Password-leg ("pending" 2FA) token consumption timing in `apiPasskeyLoginFinish` | consumed BEFORE `wa.FinishLogin`'s cryptographic verification — a failed/rejected assertion still burned the password leg | consumed AFTER a successful `FinishLogin` AND a passed `CloneWarning` check — a rejected assertion leaves the password leg intact for a retry | **changed, not regressed** — this is a real behavior difference from `main` this report found by diffing (not called out as a checked line item by either the recon or migration report's own capability table), confirmed both ways by this report's own `TestVerifierRejectedLoginDoesNotBurnPendingToken`: the password leg survives a rejected attempt AND is still consumed exactly once, on the eventual success. RP-internal, not an `authcore` friction point — noted here because it was found in the course of this verification and belongs on the record. |

**No capability loss identified.** One behavior improved (see the last row)
without the change being explicitly claimed as a capability decision by
either report that preceded this one.

### Verification performed for this report

- `git status`/`git diff main --stat` against the actual working tree
  (branch-to-branch diff is empty; nothing here is committed) — run
  directly, not trusted from the migration's own numbers, which it
  otherwise confirmed.
- `git show main:internal/app/passkey.go` diffed line-by-line against the
  working copy; every hunk read, not sampled.
- `GOWORK=off go build ./...`, `go vet ./...`, `gofmt -l .` — clean.
- `GOWORK=off go test ./... -race -count=1` — full suite, run twice from a
  clean invocation (once before this report's own new tests were added,
  once after); `internal/app` at ~141s both times, within the range this
  package's tests are known to take.
- `go-webauthn` v0.17.4 vs v0.18.1 `credential.go`/`authenticator.go`
  diffed directly in the local module cache, not trusted from the
  migration's claim.
- `authcore/passkey`'s five source files read in full: `passkey.go`,
  `registration.go`, `authentication.go`, `credential_store.go`,
  `session_store.go`.
- Three new tests written independently of the migration's own
  `passkey_authcore_test.go` (different helpers, different server fixture,
  different construction of the legacy-JSON case), all passing under
  `-race`: a legacy-credential-JSON login, a rejected-login-does-not-burn-
  pending-token round trip (including a genuine retry against the surviving
  token), and a production-path (not test-only-helper) origin/RP-ID
  hot-reconfiguration check.
- `git log --oneline --all | grep 2137c0f` in this repo, confirming the
  pinned `authcore` commit is exactly the one immediately after `audit` was
  removed (`2137c0f refactor: remove audit (#8)`).
