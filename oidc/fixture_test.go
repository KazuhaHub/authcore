package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

type testCode struct {
	nonce, challenge, redirect string
	used                       bool
}
type testIDP struct {
	publicKey                crypto.PublicKey
	algorithm                string
	server                   *httptest.Server
	issuer, clientID, secret string
	key                      *rsa.PrivateKey
	signer                   jose.Signer
	methods                  []string
	mode                     string
	editClaims               func(map[string]any)
	editMetadata             func(map[string]any)
	mu                       sync.Mutex
	codes                    map[string]*testCode
	tokenCalls               atomic.Int32
	jwksCalls                atomic.Int32
	captured                 atomic.Int32
}

func newTestIDP(t *testing.T, configure func(*testIDP)) *testIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "fixture-key"))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := randomValue()
	if err != nil {
		t.Fatal(err)
	}
	f := &testIDP{key: key, publicKey: &key.PublicKey, algorithm: "RS256", signer: signer, clientID: "fixture-client", secret: secret, methods: []string{string(ClientSecretBasic)}, codes: map[string]*testCode{}}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.issuer = "https://" + f.server.Listener.Addr().String()
	f.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	if configure != nil {
		configure(f)
	}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	return f
}
func (f *testIDP) config() Config {
	return Config{IssuerURL: f.issuer, ClientID: f.clientID, ClientSecret: f.secret, RedirectURL: "https://console.example.test/callback", Scopes: []string{"email", "profile"}, HTTPClient: f.server.Client()}
}
func (f *testIDP) metadata(w http.ResponseWriter) {
	data := map[string]any{"issuer": f.issuer, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/jwks", "response_types_supported": []string{"code"}, "id_token_signing_alg_values_supported": []string{f.algorithm}}
	if f.methods != nil {
		data["token_endpoint_auth_methods_supported"] = f.methods
	}
	if f.editMetadata != nil {
		f.editMetadata(data)
	}
	w.Header().Set("Content-Type", "application/json")
	if f.mode == "oversized-discovery" {
		w.(http.Flusher).Flush()
	}
	json.NewEncoder(w).Encode(data)
	if f.mode == "oversized-discovery" {
		io.WriteString(w, strings.Repeat(" ", 5000))
	}
}
func (f *testIDP) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		if f.mode == "redirect-discovery" {
			http.Redirect(w, r, f.server.URL+"/metadata", 302)
			return
		}
		if f.mode == "redirect-http" {
			http.Redirect(w, r, strings.Replace(f.server.URL, "https://", "http://", 1)+"/capture", 302)
			return
		}
		if f.mode == "hang-discovery" {
			<-r.Context().Done()
			return
		}
		f.metadata(w)
	case "/metadata":
		f.metadata(w)
	case "/authorize":
		values := r.URL.Query()
		if values.Get("client_id") != f.clientID || values.Get("response_type") != "code" || values.Get("code_challenge_method") != "S256" || !canonicalValue(values.Get("nonce")) || !canonicalValue(values.Get("state")) {
			http.Error(w, "invalid authorization request", 400)
			return
		}
		code, err := randomValue()
		if err != nil {
			http.Error(w, "fixture unavailable", 500)
			return
		}
		f.mu.Lock()
		f.codes[code] = &testCode{nonce: values.Get("nonce"), challenge: values.Get("code_challenge"), redirect: values.Get("redirect_uri")}
		f.mu.Unlock()
		callback, err := url.Parse(values.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "invalid callback", 400)
			return
		}
		query := callback.Query()
		query.Set("code", code)
		query.Set("state", values.Get("state"))
		callback.RawQuery = query.Encode()
		http.Redirect(w, r, callback.String(), 302)
	case "/token":
		f.exchange(w, r)
	case "/jwks":
		f.jwksCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if f.mode == "oversized-jwks" {
			w.(http.Flusher).Flush()
		}
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: f.publicKey, KeyID: "fixture-key", Algorithm: f.algorithm, Use: "sig"}}})
		if f.mode == "oversized-jwks" {
			io.WriteString(w, strings.Repeat(" ", 5000))
		}
	case "/capture":
		f.captured.Add(1)
		http.Error(w, "unexpected redirected request", 500)
	default:
		http.NotFound(w, r)
	}
}
func (f *testIDP) exchange(w http.ResponseWriter, r *http.Request) {
	f.tokenCalls.Add(1)
	if r.Method != "POST" || r.ParseForm() != nil {
		http.Error(w, "invalid token request", 400)
		return
	}
	method := ClientSecretBasic
	if len(f.methods) > 0 {
		method = AuthMethod(f.methods[0])
	}
	if method == ClientSecretBasic {
		id, secret, ok := r.BasicAuth()
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
		if !ok || id != f.clientID || secret != f.secret {
			http.Error(w, "invalid client", 401)
			return
		}
	} else if method == ClientSecretPost {
		if r.Form.Get("client_id") != f.clientID || r.Form.Get("client_secret") != f.secret || r.Header.Get("Authorization") != "" {
			http.Error(w, "invalid client", 401)
			return
		}
	} else if method == PublicClient {
		if r.Form.Get("client_id") != f.clientID || r.Form.Get("client_secret") != "" || r.Header.Get("Authorization") != "" {
			http.Error(w, "invalid public client", 401)
			return
		}
	}
	f.mu.Lock()
	code, ok := f.codes[r.Form.Get("code")]
	if !ok || code.used {
		f.mu.Unlock()
		http.Error(w, "invalid grant", 400)
		return
	}
	code.used = true
	copy := *code
	f.mu.Unlock()
	if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != copy.redirect || oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != copy.challenge {
		http.Error(w, "invalid grant", 400)
		return
	}
	access := "isolated-access-token"
	digest := sha256.Sum256([]byte(access))
	claims := map[string]any{"iss": f.issuer, "sub": "opaque-subject", "aud": f.clientID, "exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": copy.nonce, "at_hash": base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2]), "email": "person@example.test", "email_verified": true}
	if f.editClaims != nil {
		f.editClaims(claims)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, "fixture claims failed", 500)
		return
	}
	signed, err := f.signer.Sign(payload)
	if err != nil {
		http.Error(w, "fixture signing failed", 500)
		return
	}
	raw, err := signed.CompactSerialize()
	if err != nil {
		http.Error(w, "fixture serialization failed", 500)
		return
	}
	if f.mode == "lost-token" {
		connection, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			connection.Close()
		}
		return
	}
	if f.mode == "redirect-token" {
		http.Redirect(w, r, f.server.URL+"/capture", 302)
		return
	}
	if f.mode == "error-body" {
		http.Error(w, f.secret+" "+r.Form.Get("code")+" "+raw, 500)
		return
	}
	if f.mode == "tampered-token" {
		pieces := strings.Split(raw, ".")
		signature := []byte(pieces[2])
		if signature[0] == 'A' {
			signature[0] = 'B'
		} else {
			signature[0] = 'A'
		}
		pieces[2] = string(signature)
		raw = strings.Join(pieces, ".")
	}
	w.Header().Set("Content-Type", "application/json")
	if f.mode == "oversized-token" {
		w.(http.Flusher).Flush()
	}
	json.NewEncoder(w).Encode(map[string]any{"access_token": access, "token_type": "Bearer", "id_token": raw, "refresh_token": "isolated-refresh-token"})
	if f.mode == "oversized-token" {
		io.WriteString(w, strings.Repeat(" ", 5000))
	}
}

func (f *testIDP) authorize(t *testing.T, p *Provider) (Authorization, string, string) {
	t.Helper()
	authorization, err := p.Begin()
	if err != nil {
		t.Fatal(err)
	}
	client := *f.server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get(authorization.URL)
	if err != nil {
		t.Fatal("fixture authorization failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 302 {
		t.Fatal("fixture rejected authorization", response.StatusCode)
	}
	target, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return authorization, target.Query().Get("code"), target.Query().Get("state")
}
