# 3. Extract clientip, remove ratelimit

Date: 2026-09-17
Status: **accepted, then partly superseded the same day.** The `ratelimit` removal
stands. The `clientip` extraction was reverted once it was measured against the
exit criteria below — see [Outcome](#outcome), which is the point of writing
those criteria down before the code existed.
Supersedes: the `ratelimit` package

## Context

`ratelimit` is the last package in authcore without a consumer. It wraps
`go-chi/httprate` for the counting and `go-chi/chi/v5/middleware` for
trusted-proxy-aware client IP extraction, and it was extracted on the assumption
that "rate limiting" was the thing three services duplicated. Measured, that
assumption does not hold.

Verified on 2026-09-17:

- **Zero consumers.** No repository in the organisation imports
  `authcore/ratelimit`, and nothing inside authcore imports it either. It is 209
  lines of production code and 253 of tests with no caller.
- **It was designed without reading any consumer's code**, which is the same
  sequence that produced `audit` (ADR 0002).

What survived the extraction is a package whose *valuable half* — resolving the
real client IP behind a reverse proxy, and noticing when the deployment has not
been configured to allow it — is bundled with a limiter half that nobody needed,
because every service already had a limiter it was content with.

## The argument that kept it alive is spent

A read-only preflight concluded MIGRATE on the strength of exactly one argument:
AlertHub had a live X-Forwarded-For defect that a shared library would fix.

AlertHub fixed that defect directly instead, in `#18`, by adding its own
`TrustedProxies` type. The defect is closed, the migration it argued for never
happened, and nothing now depends on `ratelimit` doing that job.

That leaves the picture the defect itself exposed, which is sharper than the
argument it replaced. Four implementations of the same security-critical logic
exist, and they diverge on adversarial input:

| Implementation | Has | Lacks |
|---|---|---|
| Report-Portal `internal/app/throttle.go` | notices misconfiguration (`proxySeen`, `audit.go:219`); fatals on a bad config | skipped unparseable hops (fixed in RP `#15`) |
| Passwall-Sub-Panel `internal/transport/http/router.go` | also honours `CF-Connecting-IP` and `X-Real-IP` | no misconfiguration detection |
| AlertHub `server/internal/api/trustedproxy.go` (added in `#18`) | an unparseable hop ends the chain | no misconfiguration detection |
| `authcore/ratelimit` | delegates to chi | zero consumers |

Two of the four cannot tell an operator that a proxy is in front of them and
that they have not declared it. That is precisely the condition that produced
AlertHub's defect, and precisely the thing Report-Portal's `proxySeen` would
have surfaced on day one. The bug was never in the limiter; it was in the
client-IP resolution, and in the silence around it.

## Decision

Remove `ratelimit` from authcore, and extract `authcore/clientip` in its place.

The shareable unit is *client-IP resolution behind a proxy, plus a way to notice
that the deployment is misconfigured* — not the rate limiter. Following the
`audit` precedent (ADR 0002): a package with zero consumers, designed without
reading a consumer's code, and whose production source has not changed since it
landed, is deleted rather than carried.

## Exit criteria, written before the work starts

Taken from the preflight, and to be repeated at the end of the migration:

1. If the migrated consumer still cannot bucket by real client IP behind a proxy,
   `clientip` is deleted.
2. If only one service ends up adopting it, it is not a shared package — it is
   private code in the wrong repository, and it moves back out.

These are the same tests `audit` failed. Writing them down before the code exists
is the point: `audit` was extracted on plausibility and died on measurement.

## What this costs, honestly

- `authcore/ratelimit` is deleted: 462 lines net across code and tests.
- `clientip` is new work with no consumer committed yet. That is the risk, and
  it is the same risk that killed `audit` — a package designed before its
  consumers were read. The mitigation is that this time the consumers *have*
  been read: the four implementations above were compared on input, not on
  signature, and the divergences are recorded above. If `clientip` is extracted,
  the first consumer should be AlertHub, whose implementation is the newest and
  the narrowest, and a second consumer must follow before it is called shared.

## Corroboration worth keeping

Report-Portal's `parseTrustedProxies(nil)` already defaults to loopback
(`TestUnsetTrustsLoopbackOnly`, whose comment reads *"Loopback is the default the
sibling panel uses"*). AlertHub's new default in `#18` was chosen independently,
by a different author, and landed on the same answer. Two implementations
converging on "trust loopback, say so, and refuse everything else" from opposite
directions is the strongest evidence in this document that the *policy* is
settled and only the *mechanism* is duplicated.

## Consequences

- `authcore/ratelimit` is deleted; `git log` keeps it recoverable.
- `FRICTION.md` gains an entry recording the measurement, as it did for `audit`.
- The `clientip` extraction carries its own ADR, or extends this one, and starts
  from AlertHub as the first consumer.
- Until a second consumer adopts it, `authcore/clientip` is a hypothesis, not a
  shared package — and the exit criteria above say what happens next.

## Outcome

Written after the fact, the same day.

`ratelimit` was removed exactly as decided. `clientip` was built, shipped in
v0.2.0, and AlertHub adopted it — one consumer, which the criteria above say is
not yet a shared package.

Report-Portal was then attempted as the second consumer, and **exit criterion 2
fired**: it cannot adopt this package and keep a behaviour it documents.

Report-Portal supports a `trusted_proxies: "all"` token — trust every peer —
for a listener that genuinely cannot be reached except through a proxy. Its
walk and this package's walk agree in every bounded configuration, and were
measured agreeing on three chains including the unparseable-hop case. They
diverge only when every hop is trusted:

```
peer 127.0.0.1 (trusted), X-Forwarded-For: "1.1.1.1, 203.0.113.9"

  bounded trust set   clientip = 203.0.113.9      report-portal = 203.0.113.9   agree
  "all"               clientip = 127.0.0.1        report-portal = 1.1.1.1       DIVERGE
```

Neither answer is good. With every hop trusted there is no boundary to find, so
this package falls back to the peer: behind a proxy that makes every client the
same address, which is the collapsed-limiter defect AlertHub#18 was written to
fix. Report-Portal walks to the leftmost entry instead, which keeps the limiter
working but hands it a value the client chose.

Resolving it meant either deleting `all` (a behaviour change to a documented,
security-relevant option) or changing this package's fallback (which would make
it return an attacker-influenced value in the bounded case too). The owner chose
neither: **keep `all`, and move `clientip` back out of authcore.**

So by criterion 2, the extraction is reversed. `clientip` is not a shared
package; it is AlertHub's private client-address logic, and it lives there.
`authcore` returns to four packages.

### What this exercise was worth

The extraction cost roughly a day and produced a net deletion in the end. It
bought a measurement that reasoning had not produced: the two implementations
are equivalent, *except* under a deployment mode one of them documents, and the
divergence is invisible to anyone comparing signatures or reading either
implementation alone.

That is the same lesson as `audit` (ADR 2), reached from the other direction.
`audit` failed because the shared type could not carry a field its consumer
needed. `clientip` failed because the shared walk could not carry a policy its
consumer had chosen. Both were found by measuring against a real consumer rather
than against a plausible one, and both were found before a third service was
asked to adopt anything.

The rule worth keeping: **write the exit criteria before the code, and run them
against a consumer that already exists.** The criteria here were the only reason
this was caught in a day rather than after a migration into three services.
