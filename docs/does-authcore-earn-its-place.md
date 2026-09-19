# Does authcore earn its place?

**Written 2026-09-18.** An assessment, not a decision. It exists because ADR 3 wrote
down an exit criterion — *"if only one service ends up adopting it, it is not a
shared package, it is private code in the wrong repository"* — and nobody has ever
run that criterion against the packages that survived.

Read §1 for the verdict, §4 for the per-package evidence, §5 for why the numbers
came out the way they did, and §9 for what is **not** established here.

---

## 1. Summary

Four packages. Three deployments. **One of the three uses any of them.**

The single consumer, Report-Portal, grew in three of its five measured migrations
and shrank in one. The one that shrank is the simplest package in the library.

The two deployments that do not use it are not small: Passwall-Sub-Panel is the
largest repository in the organisation, and it has its own implementation of all
four concepts — on the same four upstream libraries authcore wraps. Its versions
are smaller than authcore's in every case.

**So the honest statement is not "the extraction failed". It is narrower and
stranger: the library is not unadopted, it is unadopted in proportion to its own
size.** The packages that add real protocol hardening are the ones nobody else
has moved to; the one package that is a thin lookup is the one that paid.

That asymmetry is the finding. §5 argues it is structural rather than accidental.

---

## 2. What it is, and how it is used

Four packages, all mechanism, none carrying an application concept:

| Package | Production lines | Test lines | Wraps |
|---|---|---|---|
| `saml` | 1117 | 1149 | `crewjam/saml` |
| `passkey` | 888 | 1118 | `go-webauthn/webauthn` |
| `captcha` | 753 | 874 | `mojocn/base64Captcha` |
| `geoip` | 448 | 591 | `oschwald/maxminddb-golang` |

3206 production lines, 3732 test lines. Every one of the four sits on an upstream
library that all three deployments already depend on directly.

Two packages were removed before this document was written, both for the same
reason, and the removals are the precedent this document follows:

- `audit` — zero usable consumers (ADR 2). One consumer's audit chain hashes a
  tenant id as its second field; the shared `Event` type forbids tenant fields. No
  adapter can bridge that, because the bytes either include `org_id` or they do not.
- `ratelimit` — zero consumers (ADR 3). What was worth sharing turned out to be
  client-IP resolution, not the limiter. That was then extracted as `clientip` and
  **withdrawn the same day** when the second consumer could not adopt it without
  giving up a documented deployment mode.

So this library has a working precedent for deleting packages that do not pay, and
it has used it twice. Both times the test was "does a real consumer measurably
benefit", not "is the code good".

---

## 3. Consumers

Measured by `git grep -l 'KazuhaHub/authcore' <ref> -- '*.go'` against `origin/main`
of each repository, 2026-09-18.

| Repository | `authcore` in `go.mod` | Files importing it |
|---|---|---|
| StockAnalysisPrediction-Report-Portal | yes | **10** |
| AlertHub | no | **0** |
| Passwall-Sub-Panel | no | **0** |

Report-Portal's ten files are the whole of it: `internal/app/{saml,saml_crewjam,passkey}.go`,
`internal/captcha/captcha.go`, `internal/geoip/geoip.go`, and five test files.

Two things about that number matter and are easy to miss:

- **Report-Portal pins a pseudo-version**, not a tag:
  `github.com/KazuhaHub/authcore v0.0.0-20260917134832-99368735839d`. Three tags
  exist (`v0.1.0`, `v0.2.0`, `v0.3.0`); none is in use.
- **AlertHub has never adopted anything**, and tried exactly once — the `audit`
  migration in ADR 2, which could not be completed.

---

## 4. Per package: what the shared version adds, and what the consumer already has

### 4.1 The measurement that matters most

Passwall-Sub-Panel has its own implementation of all four concepts. Line counts are
`wc -l` over **every non-test `.go` file in the concept**, against authcore's
production files — so `saml` counts PSP's `saml.go` *and* `saml_replay.go`, and
`passkey` counts `passkey.go` *and* `session_store.go`.

| Concept | PSP files counted | PSP's own | authcore's | Difference |
|---|---|---|---|---|
| `saml` | `auth/saml.go`, `auth/saml_replay.go` | 711 | 1117 | **+406** |
| `passkey` | `passkey/passkey.go`, `session_store.go` | 537 | 888 | **+351** |
| `captcha` | `service/captcha/` | 212 | 753 | **+541** |
| `geoip` | `pkg/geoip/` | 156 | 448 | **+292** |

**authcore's version is larger in all four cases.** There is no arrangement in
which migrating Passwall-Sub-Panel to this library reduces its code.

A note on method, because it bears on how much to trust §5. The first version of
this table counted one primary file per concept, which understated PSP by 75 lines
for `saml` and `passkey` each and made the gap look wider than it is. The corrected
figures are above. The conclusion did not change, but the *magnitude* on the two
packages that matter most did — which is the kind of error that would have been
found by the first expert to open the repository, and it is worth assuming there are
others of the same kind (§9).

That is not by itself an argument against the library — a shared package can
legitimately be larger, because it has to be general. §5 examines whether the
generality is buying anything.

### 4.2 `saml` — the one package where the increment is concrete

`authcore/saml`'s own package doc names exactly what it adds over `crewjam/saml`.
Read against what Passwall-Sub-Panel already has, the claims resolve as follows.
Each row was checked in the upstream source and in PSP's source, not inferred.

| Claim | Does `crewjam` do it? | Does PSP have it? | Real increment for PSP? |
|---|---|---|---|
| Assertion replay | **no** — keeps no record | **yes**, its own (`saml_replay.go`, replay cache keyed on assertion ID, with a hard reject on a missing ID) | **no** |
| Multiple assertions | **no** — returns the first that validates | **no** | **yes** |
| Decompression bombs | n/a to PSP — it receives POST-bound responses only, and uses the Redirect binding outbound only | n/a | **no** |
| Absent `Destination` | **partially** — `service_provider.go:1008` checks it only when `responseHasSignature || response.Destination != ""` | **no** — no `Destination` handling anywhere in `internal/service/auth/` | **yes** |

So the SAML increment for Passwall-Sub-Panel is **two gaps**: the multi-assertion
selection and the unsigned-Response Destination bypass. The replay claim, which is
the most prominent one in the package doc, is already implemented by the consumer.

Both remaining gaps are real. Neither is theoretical: `crewjam`'s own comment at
`service_provider.go:1088` says, in full —

> *"if we have at least one assertion, return the first one. It is almost universally
> true that valid responses contain only one assertion. This is less that fully
> correct, but we didn't realize that there could be more than one assertion at the
> time of establishing the public interface of `ParseXMLResponse()`, so for
> compatibility we return the first one."*

That is a known, acknowledged, deliberately-unfixed gap, not a hypothetical.

For **Report-Portal**, which did migrate, the recorded outcome was 596 → 593
production lines and a net **+58 lines in tests**. Its migration report names the
benefit specifically: *"an attacker cannot smuggle a second `Assertion` element
past this SP's signature check anymore"* — the same multi-assertion gap.

### 4.3 The other three

- **`passkey`.** PSP's version enforces the same ceremony properties the shared one
  does — it forces `UserVerification=Required` on the discoverable path (its own
  comment explains why), and it stores and advances the signature counter. The
  recorded migration for Report-Portal was 373 → **554 lines (+181)**. Its report
  justifies the growth as "the responsibility for getting ceremony orchestration
  right moved", which is a real thing to buy — but it was bought at a +181 line
  cost by the only consumer that has bought it.
- **`captcha`.** Report-Portal: 216 → 241 (+25). PSP has 212 lines of its own.
- **`geoip`.** Report-Portal: 171 → **82 (−89)**. This is the only migration in the
  whole series that removed code, and it is the simplest thing in the library — a
  lookup with no opinions. PSP has 156 lines of its own.

---

## 5. The pattern, and why it may be structural

Look at the five measured migrations in one line each:

| Package | Report-Portal Δ | What the shared version adds |
|---|---|---|
| `geoip` | **−89** | nothing — a lookup |
| `saml` | −3 (+58 in tests) | multi-assertion, Destination bypass |
| `captcha` | +25 | configuration knobs |
| `passkey` | +181 | ceremony orchestration |
| `audit` | +195 | *(removed)* |

**The line cost tracks the amount of protocol judgement the package carries, and
that is exactly backwards from where the value is.** The packages that add real
hardening are the ones that cost the most lines to adopt, because hardening is
conditional logic, and conditional logic is what a generic version must carry for
callers it does not have.

The mechanism is visible in §4.1: authcore's `captcha` is 541 lines larger than
PSP's `captcha`. A captcha is "issue a challenge, verify an answer". The only way a
generality-respecting version of that grows 3.5× is configurability — provider
dispatch, per-call construction, capacity/TTL/timeout knobs. Report-Portal's own
migration report attributes roughly 95 of its +25 lines to precisely that, and 15
of those to compensating for an authcore footgun.

So the finding is not "the packages are bad". It is:

> **A mechanism package is larger than its consumer's version exactly in proportion
> to how many consumers it is written to serve. With one consumer, that generality
> is pure cost, and it is largest precisely for the packages where the shared
> version is most valuable — because protocol judgement is what makes a package
> worth sharing and what makes a generic version large.**

ADR 2 reached the same place from one direction (a shared type that could not carry
a needed field). ADR 3 reached it from another (a shared walk that could not carry a
chosen policy). This is the third face of it: the shared version is bigger *because*
it is shared, and there is nobody to share it with.

---

## 6. Against ADR 3's exit criteria

The criterion, verbatim:

> *"If only one service ends up adopting it, it is not a shared package — it is
> private code in the wrong repository, and it moves back out."*

Applied per package today:

| Package | Adopters | Criterion outcome |
|---|---|---|
| `saml` | 1 (Report-Portal) | not shared |
| `passkey` | 1 (Report-Portal) | not shared |
| `captcha` | 1 (Report-Portal) | not shared |
| `geoip` | 1 (Report-Portal) | not shared |

**Every package fails it.** The criterion is written per package and admits no
"but the code is good" exception — which is consistent with how `audit` and
`ratelimit` were handled.

If the criterion is taken literally, the outcome is that all four become private
code in Report-Portal and this repository closes. That is a real option and it
should be stated plainly rather than softened.

---

## 7. The case for keeping, stated as strongly as I can

The criterion above has a flaw worth naming before anyone acts on it: **it was
written assuming the answer to "why one consumer" is "nobody wants it", and here the
answer is different.** Passwall-Sub-Panel and AlertHub do not use these packages
because nobody asked them to, not because they looked and declined. Neither was ever
migrated. There is no evidence of a rejection.

Against deletion:

1. **The four packages are security-relevant and correct.** `saml` closes two
   acknowledged `crewjam` gaps; `passkey` owns ceremony orchestration. Deleting them
   moves that logic into one application, where the other two cannot benefit even if
   they later want to.
2. **The line-count argument cuts both ways.** The +181 for `passkey` is recorded as
   "a real cost, honestly reported". But a security control is not bought to save
   lines. If the shared `passkey` prevents one ceremony-orchestration mistake that
   PSP's 537-line version is capable of making, the +181 is cheap.
3. **Passwall-Sub-Panel has never been given the choice.** Verified: `origin/main`
   carries no reference to `authcore` at all — not an import, not a config entry,
   not a comment — and there is no branch, commit or closed PR recording a migration
   attempt. Concluding "unshared" from "unattempted" is measuring nothing. **This is
   the strongest argument here, and it applies to one of the two non-consumers, not
   both** — see §9.5.
4. **Deletion is not obviously reversible in practice.** ADR 2 notes `git log` keeps
   it recoverable, which is true, but a deleted package with no consumers also has no
   one maintaining it.

---

## 8. What would change the answer

In rough order of decisiveness:

1. **Migrate one of the two non-consumers.** Passwall-Sub-Panel is the informative
   one, because its own implementations exist and are smaller. An honest migration
   there would answer, per package, whether the generality earns its size. If it
   does not, §5's argument stops being a hypothesis.
2. **Or decide the criterion was written for a different situation, and say so.**
   If four packages with one consumer are acceptable because the alternative is
   per-application security logic, that is a defensible position — but it is a
   *different* exit criterion from the one on record, and it should replace it
   explicitly rather than being assumed.
3. **Tag and pin.** Report-Portal sits on a pseudo-version while three tags exist.
   Whatever is decided, that is drift worth fixing; it also makes "who depends on
   what" answerable.

---

## 9. What is NOT established here

Stated so that nobody reads more into this than it says.

1. **No migration was attempted for this document.** The Passwall-Sub-Panel numbers
   in §4.1 are raw `wc -l` over each concept's files. That is not a migration
   estimate. A real one would count the call sites, the tests, the config changes
   and the behaviour that could not be carried — §5's argument would survive that or
   it would not, and this document does not test it. The first version of that table
   was itself wrong in the consumer's disfavour (§4.1); assume the rest of the
   figures here are only as good as the method stated for each.
2. **PSP's `captcha` and `geoip` were not compared functionally**, only by size.
   authcore's `geoip` has hot-reload; PSP's may not. The +292 is not evidence that
   PSP's version is worse, and I did not check whether it is.
3. **PSP's `passkey` was not compared protection-by-protection** the way `saml` was.
   The UV enforcement and counter handling were checked; the rest was not.
4. **AlertHub was not examined at all**, beyond establishing that it imports nothing.
5. **"Never given the choice" (§7.3) holds for Passwall-Sub-Panel and not for
   AlertHub, and I had this wrong in an earlier draft.** AlertHub has been given the
   choice twice: the `audit` migration, which could not be completed and ended in the
   package being deleted (ADR 2), and `clientip`, which was built for it, adopted,
   and withdrawn the same day when the second consumer could not use it (ADR 3).
   So AlertHub is not an untested deployment — it is a deployment that has twice
   found the library unable to carry what it needed. That weakens §7 considerably,
   and the asymmetry between the two non-consumers is the thing I would want an
   expert to look at first.
6. **The +58 test-line figure for `saml` and the +181 for `passkey` are quoted from
   `FRICTION.md`**, which was written by the migrations themselves. I verified the
   `geoip` 171 → 82 and the `audit` 545 → 740 figures are internally consistent with
   the tables around them; I did not re-derive any of them from the repositories.
