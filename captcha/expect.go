package captcha

import (
	"context"
	"crypto/subtle"
)

// Expect lists the values a caller requires the provider to echo back from
// siteverify. An empty field means "do not check".
type Expect struct {
	// Action is the action name set on the widget (Turnstile, reCAPTCHA v3).
	Action string
	// CData is the customer data set on the widget (Turnstile only).
	CData string
}

// VerifyExpect is Verify plus validation of the provider's action and cdata,
// as Cloudflare's Turnstile documentation recommends doing server-side. The
// expectations are folded into Result.Success the same way hostname pinning
// is: a mismatch sets Success to false and the matching ActionMismatch or
// CDataMismatch flag, and both flags can be set alongside HostnameMismatch.
//
// A non-empty expectation fails when the provider returned a different value
// or no value at all, so a provider that does not support the field (see
// Result.Action and Result.CData) can never satisfy it. An empty field in
// want is not checked, so an empty Expect behaves exactly like Verify.
//
// Errors from Verify are returned unchanged. If the provider itself rejected
// the token, its reply carries no meaningful action or cdata, so the
// mismatch flags are left false and only the provider's verdict is reported.
func (v *TokenVerifier) VerifyExpect(ctx context.Context, token, remoteIP string, want Expect) (Result, error) {
	result, err := v.Verify(ctx, token, remoteIP)
	if err != nil {
		return result, err
	}
	// Success is false here either because the provider rejected the token
	// or because hostname pinning did; only the latter means the provider
	// accepted it and its action and cdata are worth comparing.
	if !result.Success && !result.HostnameMismatch {
		return result, nil
	}

	if want.Action != "" && !equalSecret(result.Action, want.Action) {
		result.Success = false
		result.ActionMismatch = true
	}
	if want.CData != "" && !equalSecret(result.CData, want.CData) {
		result.Success = false
		result.CDataMismatch = true
	}
	return result, nil
}

// equalSecret compares in constant time. An empty got never equals a
// non-empty want, which is what makes a missing value fail closed.
func equalSecret(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
