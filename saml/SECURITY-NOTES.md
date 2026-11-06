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

Encrypted assertions are opaque to this preflight. The optional encrypted path
still requires a dependency-level resolution and separate signed/encrypted
regressions. Existing encrypted-assertion policy is unchanged. This change does
not close the dependency advisory or make a downstream scan clean.
