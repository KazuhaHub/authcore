# 1. What belongs in authcore

Date: 2026-09-17
Status: accepted

## Context

authcore currently holds `saml`, `passkey`, `audit`, `captcha`, `geoip` and
`ratelimit`. (`audit` was removed after this was written — see ADR 2.) Two of those — `geoip` especially — are not authentication. They
are signals you feed into a decision about whether a request is suspicious.

That matters because of what is coming. Passwall-Sub-Panel needs to detect
subscription sharing: one account used from many places at once. That work
wants impossible-travel calculations, concurrent-session counting, maybe device
fingerprinting. None of it is authentication, and all of it would reach for
`geoip`.

So: does a module named authcore have any business holding risk-control
primitives? Two ways out were considered — rename the module to something
broad enough to cover both, or split the risk half into a second module.

## Decision

Neither, for now. The name stays, the contents stay, and the scope gets
written down instead.

**authcore is identity protocol orchestration, plus the controls that protect
authentication flows.**

Every package here has to answer one question: *does it protect an
authentication flow?*

- `saml`, `passkey`, and the forthcoming `oidc` are the flows themselves.
- `captcha` and `ratelimit` protect login and registration from abuse. In
  scope.
- `audit` was in scope on the same reasoning — authentication events are the
  thing most worth having a trustworthy record of. It was removed anyway, for a
  reason this rule could not catch: it measured badly against two real
  consumers. See ADR 2. Passing the scope test is necessary, not sufficient.
- `geoip` answers "where did this login come from". In scope.

A package that cannot answer that question belongs somewhere else, even if it
is obviously security-related.

## Why not rename it

A precise name is a feature. "Should this go in authcore?" is a question with
an answer, and asking it stops things drifting in. "Should this go in
securekit?" is not a question at all — anything passes.

The red team on the extraction plan named "the shared library becomes a junk
drawer" as a real failure mode for a library with one maintainer. A name that
makes a bad addition feel awkward is the cheapest guard against that, and
widening the name would throw it away.

Renaming is also cheapest right now — no tags, no external consumers, one
in-flight migration on a local branch. That cuts both ways: it is a reason to
decide deliberately now rather than drift, not a reason to change.

## Why not split out a risk module yet

All three consumers need both halves today:

| Consumer | Identity | Abuse and signals |
|---|---|---|
| Passwall-Sub-Panel | saml, passkey | geoip, captcha, ratelimit |
| Report-Portal | saml, passkey | geoip, captcha |
| AlertHub | passkey | ratelimit |

Splitting would shrink nobody's dependency graph and would add a repository, a
CI pipeline and a release process for a single maintainer to carry. Go does not
link packages you do not import, so the cost of the unused half is module-graph
noise and Dependabot churn, not binary size — and with every consumer using
both halves, there is not even that.

`geoip` in particular is a lookup primitive, not a risk policy. Two domains
using it does not divide it, any more than TLS and git sharing SHA-256 divides
that.

## When to revisit

**Split when the risk side grows a second non-trivial package.** Impossible
travel and concurrent-session counting together would be enough: at that point
the risk half has its own reason to exist, and `geoip` can move with it or
stay, whichever reads better then.

Splitting stays cheap because these packages do not import each other —
`geoip`, `captcha` and `ratelimit` have no authcore dependencies at all. Keep
it that way and the split is a `git mv` and a `go.mod`.

## A note on the risk work itself

When shared-account detection does get built, the same rule as everywhere else
applies: share mechanism, not policy.

- Mechanism, and shareable: given two logins with times and locations, compute
  the implied travel speed. Count distinct sessions for an identifier in a
  window. Map an address to an ASN.
- Policy, and not shareable: how many locations count as sharing, what the
  threshold is per plan, and whether a hit throttles, warns or bans.

Detection also needs history — "how many cities in the last day" is state, and
state lives in each service's own database. A shared package can score a pair
of observations; it cannot own the record of them.

Putting thresholds and enforcement in a shared library would rebuild the
`identity` package this project already declined to build, for the same reason:
the three services would not agree, and the library would fill with
conditionals until nobody dared touch it.
