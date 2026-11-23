package captcha_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/KazuhaHub/authcore/captcha"
)

func replyWith(t *testing.T, body map[string]any) *siteverifyStub {
	t.Helper()
	return newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
		jsonReply(t, w, 0, body)
	})
}

func TestVerify_ExposesActionAndCData(t *testing.T) {
	stub := replyWith(t, map[string]any{"success": true, "action": "login", "cdata": "sess-1"})
	res, err := newVerifier(t, stub.srv.URL).Verify(context.Background(), "tok", "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Action != "login" || res.CData != "sess-1" {
		t.Fatalf("Action, CData = %q, %q; want login, sess-1", res.Action, res.CData)
	}
	if res.ActionMismatch || res.CDataMismatch {
		t.Fatal("Verify must never set mismatch flags")
	}
}

func TestVerifyExpect_Match(t *testing.T) {
	stub := replyWith(t, map[string]any{"success": true, "action": "login", "cdata": "sess-1"})
	res, err := newVerifier(t, stub.srv.URL).VerifyExpect(context.Background(), "tok", "", captcha.Expect{Action: "login", CData: "sess-1"})
	if err != nil {
		t.Fatalf("VerifyExpect: %v", err)
	}
	if !res.Success || res.ActionMismatch || res.CDataMismatch {
		t.Fatalf("result = %+v; want success with no mismatch", res)
	}
}

func TestVerifyExpect_Mismatch(t *testing.T) {
	stub := replyWith(t, map[string]any{"success": true, "action": "signup", "cdata": "other"})
	v := newVerifier(t, stub.srv.URL)
	tests := []struct {
		name             string
		want             captcha.Expect
		action, cdataBad bool
	}{
		{"action", captcha.Expect{Action: "login"}, true, false},
		{"cdata", captcha.Expect{CData: "sess-1"}, false, true},
		{"prefix is not a match", captcha.Expect{Action: "sign"}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := v.VerifyExpect(context.Background(), "tok", "", tt.want)
			if err != nil {
				t.Fatalf("VerifyExpect: %v", err)
			}
			if res.Success {
				t.Fatal("Success = true on a mismatch")
			}
			if res.ActionMismatch != tt.action || res.CDataMismatch != tt.cdataBad {
				t.Fatalf("flags = action %v cdata %v; want %v %v", res.ActionMismatch, res.CDataMismatch, tt.action, tt.cdataBad)
			}
		})
	}
}

func TestVerifyExpect_MissingValueFailsClosed(t *testing.T) {
	stub := replyWith(t, map[string]any{"success": true})
	v := newVerifier(t, stub.srv.URL)

	res, err := v.VerifyExpect(context.Background(), "tok", "", captcha.Expect{Action: "login"})
	if err != nil {
		t.Fatalf("VerifyExpect: %v", err)
	}
	if res.Success || !res.ActionMismatch || res.CDataMismatch {
		t.Fatalf("result = %+v; want failure with only ActionMismatch", res)
	}

	res, err = v.VerifyExpect(context.Background(), "tok", "", captcha.Expect{CData: "x"})
	if err != nil {
		t.Fatalf("VerifyExpect: %v", err)
	}
	if res.Success || res.ActionMismatch || !res.CDataMismatch {
		t.Fatalf("result = %+v; want failure with only CDataMismatch", res)
	}
}

func TestVerifyExpect_EmptyExpectEqualsVerify(t *testing.T) {
	for _, body := range []map[string]any{
		{"success": true, "action": "login", "cdata": "x", "hostname": "a.example.com"},
		{"success": true},
		{"success": true, "hostname": "evil.example.com"},
		{"success": false, "error-codes": []string{"timeout-or-duplicate"}},
	} {
		stub := replyWith(t, body)
		v := newVerifier(t, stub.srv.URL, captcha.WithAllowedHostnames("panel.example.com"))
		want, err := v.Verify(context.Background(), "tok", "")
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		got, err := v.VerifyExpect(context.Background(), "tok", "", captcha.Expect{})
		if err != nil {
			t.Fatalf("VerifyExpect: %v", err)
		}
		if got.Success != want.Success || got.Action != want.Action || got.CData != want.CData ||
			got.Hostname != want.Hostname || got.HostnameMismatch != want.HostnameMismatch || got.ActionMismatch || got.CDataMismatch ||
			len(got.ErrorCodes) != len(want.ErrorCodes) {
			t.Fatalf("VerifyExpect(Expect{}) = %+v; Verify = %+v", got, want)
		}
	}
}

func TestVerifyExpect_ProviderRejectionLeavesFlagsClear(t *testing.T) {
	stub := replyWith(t, map[string]any{"success": false, "error-codes": []string{"invalid-input-response"}})
	res, err := newVerifier(t, stub.srv.URL).VerifyExpect(context.Background(), "tok", "", captcha.Expect{Action: "login", CData: "x"})
	if err != nil {
		t.Fatalf("VerifyExpect: %v", err)
	}
	if res.Success || res.ActionMismatch || res.CDataMismatch {
		t.Fatalf("result = %+v; want plain provider rejection", res)
	}
}

func TestVerifyExpect_CombinesWithHostnamePinning(t *testing.T) {
	stub := replyWith(t, map[string]any{"success": true, "hostname": "evil.example.com", "action": "signup", "cdata": "other"})
	v := newVerifier(t, stub.srv.URL, captcha.WithAllowedHostnames("panel.example.com"))

	res, err := v.VerifyExpect(context.Background(), "tok", "", captcha.Expect{Action: "login", CData: "sess-1"})
	if err != nil {
		t.Fatalf("VerifyExpect: %v", err)
	}
	if res.Success || !res.HostnameMismatch || !res.ActionMismatch || !res.CDataMismatch {
		t.Fatalf("result = %+v; want all three mismatch flags set", res)
	}

	// Hostname fine, expectations met: still passes.
	stub = replyWith(t, map[string]any{"success": true, "hostname": "panel.example.com", "action": "login"})
	v = newVerifier(t, stub.srv.URL, captcha.WithAllowedHostnames("panel.example.com"))
	res, err = v.VerifyExpect(context.Background(), "tok", "", captcha.Expect{Action: "login"})
	if err != nil || !res.Success {
		t.Fatalf("res, err = %+v, %v; want success", res, err)
	}

	// Hostname wrong only: expectations met must not mask it.
	stub = replyWith(t, map[string]any{"success": true, "hostname": "evil.example.com", "action": "login"})
	v = newVerifier(t, stub.srv.URL, captcha.WithAllowedHostnames("panel.example.com"))
	res, err = v.VerifyExpect(context.Background(), "tok", "", captcha.Expect{Action: "login"})
	if err != nil {
		t.Fatalf("VerifyExpect: %v", err)
	}
	if res.Success || !res.HostnameMismatch || res.ActionMismatch {
		t.Fatalf("result = %+v; want hostname mismatch only", res)
	}
}

func TestVerifyExpect_ErrorReturnedUnchanged(t *testing.T) {
	stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	res, err := newVerifier(t, stub.srv.URL).VerifyExpect(context.Background(), "tok", "", captcha.Expect{Action: "login"})
	if !errors.Is(err, captcha.ErrBadStatus) {
		t.Fatalf("err = %v; want ErrBadStatus", err)
	}
	if res.Success || res.ActionMismatch || res.CDataMismatch {
		t.Fatalf("result = %+v; want zero Result", res)
	}
}

func TestVerifyExpect_EmptyToken_NoNetworkCall(t *testing.T) {
	called := false
	stub := newSiteverifyStub(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		jsonReply(t, w, 0, map[string]any{"success": true, "action": "login"})
	})
	res, err := newVerifier(t, stub.srv.URL).VerifyExpect(context.Background(), "", "", captcha.Expect{Action: "login"})
	if err != nil {
		t.Fatalf("VerifyExpect: %v", err)
	}
	if res.Success || res.ActionMismatch || res.CDataMismatch || called {
		t.Fatalf("result = %+v, called = %v; want a plain rejection with no network call", res, called)
	}
}

func TestVerifyExpect_PinningWithoutReportedHostname(t *testing.T) {
	stub := replyWith(t, map[string]any{"success": true, "action": "login"})
	v := newVerifier(t, stub.srv.URL, captcha.WithAllowedHostnames("panel.example.com"))

	res, err := v.VerifyExpect(context.Background(), "tok", "", captcha.Expect{Action: "login"})
	if err != nil || !res.Success || res.HostnameMismatch {
		t.Fatalf("res, err = %+v, %v; want success (pinning skips an unreported hostname)", res, err)
	}
	res, err = v.VerifyExpect(context.Background(), "tok", "", captcha.Expect{Action: "other"})
	if err != nil || res.Success || !res.ActionMismatch || res.HostnameMismatch {
		t.Fatalf("res, err = %+v, %v; want only ActionMismatch", res, err)
	}
}

func TestVerifyExpect_ProvidersWithoutFieldsNeverSatisfy(t *testing.T) {
	stub := replyWith(t, map[string]any{"success": true})
	for _, p := range []captcha.Provider{captcha.ProviderRecaptcha, captcha.ProviderHCaptcha} {
		v, err := captcha.NewTokenVerifier(p, testSecret, captcha.WithEndpoint(stub.srv.URL))
		if err != nil {
			t.Fatalf("NewTokenVerifier(%s): %v", p, err)
		}
		res, err := v.VerifyExpect(context.Background(), "tok", "", captcha.Expect{CData: "x"})
		if err != nil || res.Success || !res.CDataMismatch {
			t.Fatalf("%s: res, err = %+v, %v; want CDataMismatch failure", p, res, err)
		}
		res, err = v.VerifyExpect(context.Background(), "tok", "", captcha.Expect{Action: "login"})
		if err != nil || res.Success || !res.ActionMismatch {
			t.Fatalf("%s: res, err = %+v, %v; want ActionMismatch failure", p, res, err)
		}
	}
}

// A provider rejection must stay a plain rejection even if hostname pinning
// would also fail: the provider's own verdict, not Success, decides whether
// expectations are evaluated.
func TestVerifyExpect_UsesProviderVerdictNotSuccess(t *testing.T) {
	stub := replyWith(t, map[string]any{"success": false, "hostname": "evil.example.com", "action": "signup", "error-codes": []string{"timeout-or-duplicate"}})
	v := newVerifier(t, stub.srv.URL, captcha.WithAllowedHostnames("panel.example.com"))
	res, err := v.VerifyExpect(context.Background(), "tok", "", captcha.Expect{Action: "login"})
	if err != nil {
		t.Fatalf("VerifyExpect: %v", err)
	}
	if res.Success || res.ActionMismatch || res.HostnameMismatch || len(res.ErrorCodes) != 1 {
		t.Fatalf("result = %+v; want a plain provider rejection with ErrorCodes", res)
	}
}
