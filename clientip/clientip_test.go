package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func req(peer, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = peer
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func mustParse(t *testing.T, spec string) TrustedProxies {
	t.Helper()
	tp, err := Parse(spec)
	if err != nil {
		t.Fatalf("Parse(%q): %v", spec, err)
	}
	return tp
}

// TestZeroValueIgnoresForwardedFor pins the compatibility promise: unconfigured,
// the answer is the TCP peer and nothing else. A set that has not been
// configured can never be talked into believing a header.
func TestZeroValueIgnoresForwardedFor(t *testing.T) {
	var tp TrustedProxies
	if tp.Configured() {
		t.Fatal("the zero value must not report itself as configured")
	}
	if got := tp.ClientIP(req("127.0.0.1:9999", "203.0.113.9")); got != "127.0.0.1" {
		t.Fatalf("ClientIP = %q, want the peer 127.0.0.1", got)
	}
}

// TestTrustedPeerGetsTheForwardedClient is the direction that must NOT break:
// behind a declared proxy, the client is the forwarded address, not the proxy.
// A package that stopped honouring the header would collapse every caller into
// one bucket and nothing else in this file would notice.
func TestTrustedPeerGetsTheForwardedClient(t *testing.T) {
	tp := Loopback()
	if got := tp.ClientIP(req("127.0.0.1:54321", "203.0.113.9")); got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q, want the forwarded client 203.0.113.9", got)
	}
}

// TestUntrustedPeerCannotSpoofTheHeader is the other half. Believing a header
// from a peer that was never declared would let any client mint a new identity
// per request, so an untrusted peer is keyed on its own address no matter what
// it claims.
func TestUntrustedPeerCannotSpoofTheHeader(t *testing.T) {
	tp := Loopback()
	if got := tp.ClientIP(req("198.51.100.99:44444", "203.0.113.9")); got != "198.51.100.99" {
		t.Fatalf("ClientIP = %q, want the peer 198.51.100.99, not the claimed 203.0.113.9", got)
	}

	// Rotating the forged value must not change the answer, which is the whole
	// point: a limiter keyed on this must not be handed a fresh key per request.
	for i := 0; i < 5; i++ {
		forged := "203.0.113." + string(rune('0'+i))
		if got := tp.ClientIP(req("198.51.100.99:44444", forged)); got != "198.51.100.99" {
			t.Fatalf("forged %q changed the answer to %q", forged, got)
		}
	}
}

// TestChainStopsAtTheFirstUntrustedHop covers the walk: with two chained trusted
// proxies, the client is the rightmost entry that is not one of them, and
// addresses the client wrote itself, further left, are never reached.
func TestChainStopsAtTheFirstUntrustedHop(t *testing.T) {
	tp := mustParse(t, "loopback,10.0.0.0/8")
	// The client forged 1.1.1.1; the outer proxy appended the real client
	// 203.0.113.9; the inner proxy appended 10.1.2.3.
	if got := tp.ClientIP(req("127.0.0.1:9999", "1.1.1.1, 203.0.113.9, 10.1.2.3")); got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q, want 203.0.113.9 (the first untrusted hop from the right)", got)
	}
}

// TestUnparseableHopEndsTheWalk is the fix this package inherits from
// Report-Portal#15. Skipping a hop that does not parse and carrying on would
// step past the point where custody was lost and return an address nobody
// vouched for.
//
// The chain is built so the walk actually REACHES the bad hop: everything to
// its right is trusted, which is the only shape where skipping it changes the
// answer. An earlier version of this test put an untrusted hop to the right of
// the garbage, so the walk returned before ever reaching it and the test passed
// whether or not the chain was broken -- it could not fail, and a mutation that
// swapped the stop for a skip proved it.
func TestUnparseableHopEndsTheWalk(t *testing.T) {
	tp := Loopback()
	// Right to left: 127.0.0.1 (trusted), then garbage, then 9.9.9.9.
	// Reaching 9.9.9.9 means the walk stepped over a hop it could not verify.
	got := tp.ClientIP(req("127.0.0.1:9999", "9.9.9.9, garbage, 127.0.0.1"))
	if got == "9.9.9.9" {
		t.Fatal("the walk stepped over an unparseable hop and returned an unvouched-for address")
	}
	if got != "127.0.0.1" {
		t.Fatalf("ClientIP = %q, want the peer 127.0.0.1 (the walk must stop at the bad hop)", got)
	}
}

// TestRepeatedHeadersAreWalkedInFull guards the use of Header.Values over
// Header.Get: a request carrying X-Forwarded-For twice must be walked across
// both, not only whichever copy the server kept.
func TestRepeatedHeadersAreWalkedInFull(t *testing.T) {
	tp := Loopback()
	r := req("127.0.0.1:9999", "")
	r.Header.Add("X-Forwarded-For", "203.0.113.9")
	r.Header.Add("X-Forwarded-For", "127.0.0.1")
	if got := tp.ClientIP(r); got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q, want 203.0.113.9 across both headers", got)
	}
}

// TestForwardedFromUntrustedPeer covers both answers. A caller that acted on
// the wrong one would either log a misconfiguration on every ordinary request
// or, worse, stay silent during the deployment this signal exists to catch.
func TestForwardedFromUntrustedPeer(t *testing.T) {
	tp := Loopback()
	for _, tc := range []struct {
		name    string
		subject TrustedProxies
		peer    string
		xff     string
		want    bool
	}{
		{
			name:    "forwarded request from a peer we were not told about",
			subject: tp, peer: "198.51.100.99:4444", xff: "203.0.113.9", want: true,
		},
		{
			name:    "forwarded request from a trusted peer",
			subject: tp, peer: "127.0.0.1:4444", xff: "203.0.113.9", want: false,
		},
		{
			name:    "no forwarded header at all",
			subject: tp, peer: "198.51.100.99:4444", xff: "", want: false,
		},
		{
			// An unconfigured set trusts no peer, so a forwarded request is
			// exactly the condition this reports: a proxy is in front of the
			// server and nobody has declared it.
			name:    "unconfigured set and a forwarded request",
			subject: TrustedProxies{}, peer: "127.0.0.1:4444", xff: "203.0.113.9", want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.subject.ForwardedFromUntrustedPeer(req(tc.peer, tc.xff)); got != tc.want {
				t.Fatalf("ForwardedFromUntrustedPeer = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		spec       string
		wantErr    bool
		configured bool
	}{
		{"", false, false},
		{"none", false, false},
		{"NONE", false, false},
		{"loopback", false, true},
		{"10.0.0.0/8", false, true},
		{"192.168.1.7", false, true},
		{"2001:db8::1", false, true},
		{"loopback, 10.0.0.0/8 ,192.168.1.7", false, true},
		{"all", true, false},
		{"*", true, false},
		{"0.0.0.0/0", true, false},
		{"::/0", true, false},
		{"not-an-address", true, false},
		{"10.0.0.0/99", true, false},
	} {
		tp, err := Parse(tc.spec)
		if tc.wantErr {
			if err == nil {
				t.Errorf("Parse(%q) = nil error, want one", tc.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q): %v", tc.spec, err)
			continue
		}
		if tp.Configured() != tc.configured {
			t.Errorf("Parse(%q).Configured() = %v, want %v", tc.spec, tp.Configured(), tc.configured)
		}
	}
}

// TestLoopbackCoversBothFamilies: a proxy on the same host may reach the server
// over IPv4 or IPv6, and a set that covered only one would silently stop
// honouring the header on the other.
func TestLoopbackCoversBothFamilies(t *testing.T) {
	tp := Loopback()
	for _, peer := range []string{"127.0.0.1:1234", "[::1]:1234"} {
		if got := tp.ClientIP(req(peer, "203.0.113.9")); got != "203.0.113.9" {
			t.Fatalf("peer %s: ClientIP = %q, want the forwarded client", peer, got)
		}
	}
}
