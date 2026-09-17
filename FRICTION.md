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
