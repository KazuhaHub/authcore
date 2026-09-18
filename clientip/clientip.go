// Package clientip resolves the address an HTTP request actually came from when
// the server sits behind one or more reverse proxies, and reports when the
// deployment looks misconfigured.
//
// Those two halves belong together, and separating them is what this package
// exists to avoid. Resolving the address requires deciding which peers may set
// X-Forwarded-For; getting that decision wrong is invisible, because the header
// is either believed or ignored and both look like a working server. The
// failure mode is an address that is plausible, identical for every visitor,
// and wrong -- so the only reliable way to notice it is to say so at the point
// the header is discarded.
//
// This package does not rate-limit anything, and it does not decide what to do
// about a misconfiguration. It answers "which address is this, and was I
// configured to believe it?", and the caller decides whether that is worth a
// log line, a metric, or a banner in an admin console. Sharing mechanism rather
// than policy is the rule for this module (ADR 1); the mechanism here is the
// trust boundary and the walk across it, which is the part every service was
// writing for itself and getting subtly differently right.
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// TrustedProxies is the set of peer addresses whose X-Forwarded-For header may
// be believed when deciding which client a request came from.
//
// The zero value trusts nothing and ignores X-Forwarded-For entirely. That is
// the correct default for a server facing the internet directly, and it is also
// the safe fallback for a misconfigured deployment, because an empty set can
// never be tricked into believing a forged header.
type TrustedProxies struct {
	nets []*net.IPNet
}

// Parse reads a trusted-proxy specification:
//
//	""                    trust nothing; X-Forwarded-For is ignored
//	"none"                the same, written explicitly
//	"loopback"            127.0.0.0/8 and ::1/128, for a proxy on the same host
//	"10.0.0.0/8,192.168.1.7"
//	                      an explicit list; a bare address means that address
//
// There is deliberately no "trust everything" form. A set that accepts any peer
// makes X-Forwarded-For attacker-controlled, which hands every client an
// unlimited supply of whatever the header is used to key -- the opposite of
// what a trust boundary is for. "all", "*", "0.0.0.0/0" and "::/0" are refused
// with that reasoning rather than silently accepted.
//
// Note that "" means trust nothing here. Whether an empty configuration should
// instead default to loopback is a deployment decision, and the two services
// that use this package answer it differently, so it is left to the caller
// rather than baked into the parser.
func Parse(spec string) (TrustedProxies, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.EqualFold(spec, "none") {
		return TrustedProxies{}, nil
	}
	var tp TrustedProxies
	for _, raw := range strings.Split(spec, ",") {
		tok := strings.TrimSpace(raw)
		if tok == "" {
			continue
		}
		if strings.EqualFold(tok, "loopback") {
			for _, cidr := range []string{"127.0.0.0/8", "::1/128"} {
				_, n, err := net.ParseCIDR(cidr)
				if err != nil {
					return TrustedProxies{}, fmt.Errorf("loopback %q: %w", cidr, err)
				}
				tp.nets = append(tp.nets, n)
			}
			continue
		}
		if strings.EqualFold(tok, "all") || tok == "*" || tok == "0.0.0.0/0" || tok == "::/0" {
			return TrustedProxies{}, fmt.Errorf(
				"%q would trust every peer, making X-Forwarded-For attacker-controlled; list the proxy addresses instead", tok)
		}
		if _, n, err := net.ParseCIDR(tok); err == nil {
			tp.nets = append(tp.nets, n)
			continue
		}
		ip := net.ParseIP(tok)
		if ip == nil {
			return TrustedProxies{}, fmt.Errorf("%q is neither an IP address nor a CIDR block", tok)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		tp.nets = append(tp.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return tp, nil
}

// Loopback is the common case in one call: a reverse proxy on the same host.
// It is exactly Parse("loopback").
func Loopback() TrustedProxies {
	tp, err := Parse("loopback")
	if err != nil {
		// Unreachable: the loopback literals are compile-time constants that
		// net.ParseCIDR accepts. A panic here would be a programming error in
		// this package, not a runtime condition a caller could handle.
		panic("clientip: loopback CIDRs failed to parse: " + err.Error())
	}
	return tp
}

// Configured reports whether any proxy is trusted at all.
func (tp TrustedProxies) Configured() bool { return len(tp.nets) > 0 }

// Trusts reports whether addr is one of the peers whose header may be believed.
func (tp TrustedProxies) Trusts(addr string) bool {
	return tp.trusts(net.ParseIP(hostOnly(addr)))
}

func (tp TrustedProxies) trusts(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range tp.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP returns the address the request should be attributed to.
//
// With no trusted proxies it is the TCP peer, unchanged. Otherwise the
// X-Forwarded-For chain is walked from right to left: each entry was appended by
// the hop to its right, so entries contributed by trusted hops are themselves
// trustworthy, and the first address that is NOT a trusted proxy is the client.
//
// Anything the walk cannot vouch for falls back to the peer address. That keeps
// a spoofed header from ever becoming the answer: a client may write whatever it
// likes into X-Forwarded-For, but those values sit to the LEFT of the addresses
// the trusted proxies appended, so the walk stops before reaching them. A hop
// that does not parse ends the walk for the same reason -- every entry further
// left is unverifiable, so the chain of custody is broken rather than guessed
// past.
func (tp TrustedProxies) ClientIP(r *http.Request) string {
	peer := hostOnly(r.RemoteAddr)
	if !tp.Configured() || !tp.trusts(net.ParseIP(peer)) {
		return peer
	}
	for _, hop := range forwardedChain(r) {
		ip := net.ParseIP(hop)
		if ip == nil {
			break
		}
		if !tp.trusts(ip) {
			return ip.String()
		}
	}
	return peer
}

// ForwardedFromUntrustedPeer reports whether the request carries
// X-Forwarded-For while arriving from a peer this set does not trust.
//
// That combination means there is a reverse proxy in front of this server and
// the server has not been told to believe it. Discarding the header is still the
// right response -- believing an unvouched-for peer would let anyone claim any
// address -- but staying silent about it is not: every request is being
// attributed to the proxy, identically, and the value looks populated rather
// than missing. A plausible wrong address is worse than an absent one.
//
// This is the signal, not the response. The caller decides whether it becomes a
// log line, a counter, or a hint in an admin console. It is reported per
// request and is deliberately not remembered here, so that the package keeps no
// state and a caller that wants "has this ever happened" supplies its own.
func (tp TrustedProxies) ForwardedFromUntrustedPeer(r *http.Request) bool {
	if len(r.Header.Values("X-Forwarded-For")) == 0 {
		return false
	}
	return !tp.trusts(net.ParseIP(hostOnly(r.RemoteAddr)))
}

// hostOnly strips the port from a "host:port" peer address. A bare address is
// returned unchanged, which is what httptest and unix sockets produce.
func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// forwardedChain flattens every X-Forwarded-For header into one list, ordered
// RIGHT TO LEFT -- nearest hop first.
//
// It reads Header.Values rather than Header.Get so that a request carrying the
// header more than once is walked in full instead of on whichever copy the
// server happened to keep.
func forwardedChain(r *http.Request) []string {
	var chain []string
	for _, header := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(header, ",") {
			if tok := strings.TrimSpace(part); tok != "" {
				chain = append(chain, hostOnly(tok))
			}
		}
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}
