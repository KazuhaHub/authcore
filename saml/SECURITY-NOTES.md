# Assertion identity admission

The plaintext preflight requires exactly one assertion-namespace `Issuer` and
rejects foreign or duplicate direct `Subject` / `NameID` elements before invoking
the dependency parser. It does not authenticate XML. Signature, destination,
request, validity and replay checks still run on the original document.

This hardening addresses the plaintext structural cases described in
[GO-2026-6909](https://pkg.go.dev/vuln/GO-2026-6909). Encrypted assertions remain
opaque to this preflight, so dependency-level validation is also required.

The module now selects official `github.com/crewjam/saml v0.6.3`, tag commit
`c5725cd857625e4c1f6dbbe5e0b3822def94b581`, without a replacement. The namespace
and nil-pointer repair was merged through
[crewjam/saml#679](https://github.com/crewjam/saml/pull/679), which superseded
the closed, unmerged [#674](https://github.com/crewjam/saml/pull/674). The
dependency binds assertion fields to their namespaces, checks missing pointers,
and requires bearer confirmation and audience restrictions. The original Issuer
nil-pointer claim was not reproduced against v0.5.1, whose field is a value;
the independently reproduced NameID admission and missing-Subject panic remain
the concrete original controls. Dependencies retain their licenses.

Regression tests verify normal and malformed plaintext responses with valid
RSA-SHA256 signatures, and actual encrypted responses with a trusted signed outer
Response. They require a valid encrypted identity to survive while foreign NameID
cannot become an identity and missing Subject, Conditions or confirmation data
is rejected without a panic. Current positive fixtures use RSA-OAEP SHA-256 and
AES-256-GCM. A separate signed encrypted fixture requires legacy RSA1_5 key
transport to be refused by default; no legacy decrypter is registered. Enabling
encrypted assertions does not enable that algorithm. The dependency now emits
the standard OAEP digest URI, so the earlier fixture's digest-URI incompatibility
does not require an allowlist exception.

The new Redirect implementation escapes RelayState itself. Authcore passes the
original value once, preserving both unsigned and independently verified
RSA/ECDSA signed requests, endpoint query fields and reserved-parameter refusal.

Consumers must remove their own interim fork replacement when adopting this
version: Go does not propagate dependency replacements. They must verify the
resolved official module, checksums, scans and actual runtime. Local SAML tests
pass, including the genuine signed/encrypted controls and unsigned RelayState
regression. Current-source hosted CI and downstream deployment remain acceptance
gates. No advisory ignore or scanner exception is added.

The interim fork and its evidence remain historical. Running its encrypted
negative controls against v0.5.1 reproduced foreign NameID admission and a missing
Subject panic. The interim Linux-target source scan found no called vulnerabilities;
that result does not cover this dependency update. The old upstream package
suite rejected its XSW-7 and XSW-8 fixtures, but two tests failed because their
exact expected error text differed with the selected XML signature library.
They are not recorded as passing tests. A full local authcore test also failed
Windows GeoIP mapped-file replacement/cleanup cases. Linux CI and downstream
deployment validation remain required; no test or scanner failure is ignored.
