# 3. Extract clientip, remove ratelimit

Date: 2026-09-17
Status: **accepted** (2026-09-17). The repository owner ruled on this the same day.
Supersedes: the `ratelimit` package, if accepted

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
