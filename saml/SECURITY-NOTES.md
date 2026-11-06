# Assertion identity admission

The plaintext preflight requires exactly one assertion-namespace `Issuer` and
rejects foreign or duplicate direct `Subject` / `NameID` elements before invoking
the dependency parser. It does not authenticate XML. Signature, destination,
request, validity and replay checks still run on the original document.

This hardening addresses the plaintext structural cases described in
[GO-2026-6909](https://pkg.go.dev/vuln/GO-2026-6909). The advisory currently records
no fixed dependency version. The pinned v0.5.1 source represents `Assertion.Issuer`
as a value, whereas the advisory describes a nil-pointer dereference; that panic
has not been reproduced here. Do not describe the preflight as a verified fix for
the dependency or suppress vulnerability scanning on that basis.

Encrypted assertions are opaque to this preflight. The local module therefore
pins the dependency-level proposal in [crewjam/saml#674](https://github.com/crewjam/saml/pull/674):
`github.com/openctemio/saml v0.5.2-0.20261106014128-2b3cdad337cd`, exact Git commit
`2b3cdad337cdd14eeeeec91cd4c7405d6ec590ba`. This is an unmerged third-party fork,
not an official crewjam release. Its reviewed changes bind assertion elements to
their namespaces and check missing optional pointers before use. The proposal is
based on upstream `346540312f721498fc75e69637d9250dd89f230b`; the upstream JWT-v5
transition is also present relative to v0.5.1. Dependencies retain their licenses.

Regression tests verify normal and malformed plaintext responses with valid
RSA-SHA256 signatures, and actual encrypted responses with a trusted signed outer
Response. They require a valid encrypted identity to survive while foreign NameID
cannot become an identity and missing Subject, Conditions or confirmation data
is rejected without a panic. Encryption fixtures use the dependency's existing
legacy RSA1_5/AES128-CBC support, not a new production policy. Its OAEP fixture
emits a nonstandard digest URI rejected by the existing signature allowlist;
that separate compatibility issue has not been repaired or allowed here.

Go does not propagate a dependency module's `replace` directives. Every consumer,
including NetHub, must repeat the exact pin in its main module and verify its own
graph, checksums, scans and runtime before acceptance. This pin has not yet passed
hosted CI or downstream deployment acceptance. Do not infer a complete repair
from a clean vulnerability scan: the database may not map the original advisory
to this fork. The independent signed/encrypted regressions and source audit remain
required. No advisory ignore or scanner exception is added. Remove the replacement
when an official release containing the reviewed fixes can pass the same checks.

Local validation passed the authcore SAML package, including both signed and
encrypted regressions. Running those encrypted negative cases against v0.5.1
with the same authcore source reproduced foreign NameID admission and a missing
Subject panic. The Linux-target source scan found no called vulnerabilities with
the pin; this remains separate from source-level evidence. The upstream package
suite under this graph rejected its XSW-7 and XSW-8 fixtures, but two tests failed
because their exact expected error text differs with the selected XML signature
library. They are not recorded as passing tests. A full local authcore test also
failed Windows GeoIP mapped-file replacement/cleanup cases. Linux CI and downstream
deployment validation are still required; no test or scanner failure is ignored.
