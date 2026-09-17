# 2. audit does not belong in authcore

Date: 2026-09-17
Status: accepted
Supersedes: the `audit` package, removed by this decision

## Context

`audit` was extracted on the assumption that three services writing audit logs
meant three copies of the same thing. Two of them then tried to adopt it.

**Report-Portal** (no hash chain). `internal/app/audit.go` went from 545 lines
to 740. About 130 of the new lines are a `Store` adapter written to satisfy an
interface, and what came back was an `Event` type RP already had, `Marshal`, and
a `Chain` it does not switch on. Everything the shared model could not carry —
`ActorOU`, two timestamp formats, substring search — stayed in RP anyway. It
took on a dependency and kept all of its own code.

**AlertHub** (hash chain, used seriously: `VerifyAuditChain` behind an API, rows
exported to an external SIEM collector for independent checking). The migration
could not be attempted. `canonicalAudit` hashes the tenant id as the second
field, immediately after the previous hash:

```go
put(prevHash)
put(strconv.FormatInt(e.OrgID, 10))   // server/internal/store/audit.go:63
put(strconv.FormatInt(e.At, 10))
...
```

`authcore/audit.Event` has no field for a tenant id, and the package doc says
none should ever be added. So the options were: drop `org_id` from the hash
input and invalidate every chain already in the database — including the copies
the SIEM collector holds — or put tenancy into a package whose first paragraph
forbids it.

Verified rather than reasoned about: AlertHub's real `canonicalAudit` and
`auditHash` were copied into a scratch module, used to hash a three-row chain
the way the live database already does, translated field-for-field into
`audit.Event`, and run through `audit.Verify`. It fails on the first historical
row.

## Decision

Remove `audit` from authcore. Each service keeps its own.

Four migrations, measured:

| Package | Consumer | Chain? | Before | After | Δ |
|---|---|---|---|---|---|
| `geoip` | Report-Portal | — | 171 | 82 | **−89** |
| `captcha` | Report-Portal | — | 216 | 241 | +25 |
| `audit` | Report-Portal | no | 545 | 740 | **+195** |
| `audit` | AlertHub | yes | 468 | 468 | **blocked** |

Two real consumers, no lines saved, and the one feature that justified a shared
package is structurally unusable by the only consumer that needs it.

## Why this is not an adapter problem

An adapter can bridge a shape. It cannot bridge a hash input containing a field
the shared type is forbidden to represent. The bytes either include `org_id` or
they do not, and the existing database says they do.

The rule that caused this collision — mechanism, not policy — is still the right
rule. Tenancy *is* policy. It correctly kept tenancy out of the package, and the
consequence is that a package whose value is a hash over a tenanted record
cannot be shared with a tenanted consumer. The rule worked; it just also decided
this question.

## What this costs, honestly

`authcore/audit` was around 660 lines of code and 795 of tests, plus a real fix
landed in #7 that made a silently-dropped chain fail loudly. All of it is being
deleted.

That is the cheaper outcome. Two migrations at roughly a day each bought the
answer before the abstraction was pushed into a third service, where the sunk
cost would have argued for keeping it. Finding out here is what the exercise was
for.

## Consequences

- `authcore/audit` is deleted. `git log` keeps it recoverable, and
  `FRICTION.md`'s `## audit — the keep-or-drop measurement` has the full
  measurement.
- Report-Portal's `refactor/authcore-audit` branch is abandoned unmerged. Its
  `geoip` and `captcha` work landed separately and is unaffected.
- AlertHub's `refactor/authcore-audit` branch holds one unrelated commit fixing
  a broken `go.mod` module path (`github.com/kazuha/alerthub` against a
  repository at `github.com/KazuhaHub/AlertHub`). That is a real bug and should
  land on its own.
- Before anyone proposes `audit` to a third consumer: the question is not
  whether the API is nice, it is whether `canonicalBytes` can be made
  caller-extensible without letting policy back in. Nobody has shown that it can.

## What this says about the remaining packages

`geoip` is the only migration so far that removed more than it added, and it is
the simplest thing in the library — a lookup with no opinions. The packages
still to be measured, `saml` and `passkey`, carry real protocol orchestration
that all three services genuinely duplicate, which is a stronger case than
`audit` ever had. They should still be measured the same way, and dropped the
same way if they measure badly.
