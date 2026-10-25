// Package oidc implements the authorization-code protocol over go-oidc and
// oauth2. It adds PKCE, state/nonce checks, bounded HTTPS reads and fixed errors.
// Callers must atomically consume short-lived, browser-bound protocol state
// before Complete. Accounts, invitations, cookies and persistence are caller policy.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"time"
	"unicode/utf8"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const DefaultMaxResponseBytes int64 = 1 << 20
const DefaultTimeout = 10 * time.Second
const maxCredentialBytes = 16 * 1024

var (
	ErrNotConfigured         = errors.New("oidc: provider not configured")
	ErrInvalidConfig         = errors.New("oidc: invalid configuration")
	ErrDiscovery             = errors.New("oidc: discovery failed")
	ErrUnsupportedAuthMethod = errors.New("oidc: unsupported token authentication method")
	ErrInvalidState          = errors.New("oidc: protocol state mismatch or invalid input")
	ErrExchange              = errors.New("oidc: code exchange failed")
	ErrInvalidToken          = errors.New("oidc: invalid ID token")
	ErrNonceMismatch         = errors.New("oidc: nonce mismatch")
	ErrInvalidClaims         = errors.New("oidc: claims could not be decoded")
	ErrUnavailable           = errors.New("oidc: protocol material unavailable")
)

type AuthMethod string

const (
	ClientSecretBasic AuthMethod = "client_secret_basic"
	ClientSecretPost  AuthMethod = "client_secret_post"
	PublicClient      AuthMethod = "none"
)

type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string `json:"-"`
	RedirectURL  string
	Scopes       []string
	// HTTPClient supplies TLS roots, DNS/dial and private-network policy. Its
	// transport must honor request cancellation and must not retry token POSTs.
	// No insecure TLS option is added.
	HTTPClient *http.Client `json:"-"`
	// Empty selects one supported method from discovery, never trial exchanges.
	AuthMethod       AuthMethod
	Timeout          time.Duration
	MaxResponseBytes int64
	Now              func() time.Time `json:"-"`
}

func (Config) String() string     { return "oidc.Config(redacted)" }
func (c Config) GoString() string { return c.String() }

type Metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	AuthMethods           []string `json:"token_endpoint_auth_methods_supported"`
	SigningAlgs           []string `json:"id_token_signing_alg_values_supported"`
}

// State must be stored privately with caller-controlled expiry and browser
// binding. Fields are exported for a durable adapter, not for client responses.
// It carries no application account or identity policy.
type State struct {
	Value         string `json:"-"`
	Nonce         string `json:"-"`
	Verifier      string `json:"-"`
	Configuration string `json:"-"`
}

func (State) String() string     { return "oidc.State(redacted)" }
func (s State) GoString() string { return s.String() }

type Authorization struct {
	URL   string `json:"-"`
	State State  `json:"-"`
}

func (Authorization) String() string     { return "oidc.Authorization(redacted)" }
func (a Authorization) GoString() string { return a.String() }

// Assertion contains verified protocol data. Issuer is the literal signed claim;
// ProviderIssuer is the trusted discovery issuer (including go-oidc's documented
// Google compatibility case). The caller chooses its identity mapping explicitly.
// Token-endpoint access and refresh credentials are not returned. Claims does not fetch userinfo or
// distributed claims, and does not decide whether an email is suitable for binding.
type Assertion struct {
	Issuer         string    `json:"issuer"`
	ProviderIssuer string    `json:"provider_issuer"`
	Subject        string    `json:"subject"`
	Audience       []string  `json:"audience"`
	ExpiresAt      time.Time `json:"expires_at"`
	IssuedAt       time.Time `json:"issued_at"`
	claims         json.RawMessage
}

func (*Assertion) String() string     { return "oidc.Assertion(verified)" }
func (a *Assertion) GoString() string { return a.String() }
func (a *Assertion) Claims(destination any) error {
	if a == nil || a.claims == nil {
		return ErrNotConfigured
	}
	if err := json.Unmarshal(a.claims, destination); err != nil {
		return ErrInvalidClaims
	}
	return nil
}

type Provider struct {
	metadata      Metadata
	oauth         oauth2.Config
	verifier      *coreoidc.IDTokenVerifier
	client        *http.Client
	timeout       time.Duration
	maxBytes      int64
	configuration string
}

func (*Provider) String() string     { return "oidc.Provider(redacted)" }
func (p *Provider) GoString() string { return p.String() }

func New(ctx context.Context, config Config) (*Provider, error) {
	if ctx == nil ||
		!httpsURL(config.IssuerURL, false) ||
		!httpsURL(config.RedirectURL, true) ||
		len(config.ClientID) == 0 ||
		len(config.ClientID) > 4096 ||
		!utf8.ValidString(config.ClientID) ||
		len(config.ClientSecret) > maxCredentialBytes {
		return nil, ErrInvalidConfig
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultTimeout
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if config.Timeout < 0 || config.Timeout > time.Minute || config.MaxResponseBytes < 1 || config.MaxResponseBytes > 16<<20 {
		return nil, ErrInvalidConfig
	}
	scopes, err := normalizeScopes(config.Scopes)
	if err != nil {
		return nil, err
	}
	client := boundedClient(config.HTTPClient, config.Timeout, config.MaxResponseBytes)
	ready := false
	defer func() {
		if !ready {
			client.CloseIdleConnections()
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	ctx = coreoidc.ClientContext(ctx, client)
	upstream, err := coreoidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, failed(ctx, ErrDiscovery)
	}
	var document struct {
		Metadata
		Methods       *[]string `json:"token_endpoint_auth_methods_supported"`
		ResponseTypes []string  `json:"response_types_supported"`
	}
	if upstream.Claims(&document) != nil ||
		document.Issuer != config.IssuerURL ||
		!httpsURL(document.AuthorizationEndpoint, true) ||
		!httpsURL(document.TokenEndpoint, true) ||
		!httpsURL(document.JWKSURI, true) ||
		!slices.Contains(document.ResponseTypes, "code") {
		return nil, ErrDiscovery
	}
	metadata := document.Metadata
	if document.Methods == nil {
		metadata.AuthMethods = []string{string(ClientSecretBasic)}
	} else {
		metadata.AuthMethods = slices.Clone(*document.Methods)
	}
	metadata.SigningAlgs = acceptedAlgorithms(metadata.SigningAlgs)
	if len(metadata.SigningAlgs) == 0 {
		return nil, ErrDiscovery
	}
	method, style, err := chooseAuthMethod(config.AuthMethod, config.ClientSecret, metadata.AuthMethods)
	if err != nil {
		return nil, err
	}
	p := &Provider{metadata: metadata, client: client, timeout: config.Timeout, maxBytes: config.MaxResponseBytes}
	p.oauth = oauth2.Config{ClientID: config.ClientID, ClientSecret: config.ClientSecret, RedirectURL: config.RedirectURL, Scopes: scopes, Endpoint: oauth2.Endpoint{AuthURL: metadata.AuthorizationEndpoint, TokenURL: metadata.TokenEndpoint, AuthStyle: style}}
	// Do not inherit an insecure issuer override carried by an upstream context.
	p.verifier = coreoidc.NewVerifier(config.IssuerURL, coreoidc.NewRemoteKeySet(ctx, metadata.JWKSURI), &coreoidc.Config{ClientID: config.ClientID, SupportedSigningAlgs: slices.Clone(metadata.SigningAlgs), Now: config.Now})
	values := []string{config.IssuerURL, config.ClientID, config.RedirectURL, string(method), metadata.AuthorizationEndpoint, metadata.TokenEndpoint, metadata.JWKSURI}
	encoded := []byte("authcore/oidc/code/v1")
	for _, section := range [][]string{values, scopes, metadata.SigningAlgs} {
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(section)))
		for _, value := range section {
			encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(value)))
			encoded = append(encoded, value...)
		}
	}
	sum := sha256.Sum256(encoded)
	p.configuration = base64.RawURLEncoding.EncodeToString(sum[:])
	ready = true
	return p, nil
}

// CloseIdleConnections releases an internally created transport's idle sockets.
// Supplied transports remain caller-owned; future operations are still allowed.
func (p *Provider) CloseIdleConnections() {
	if p != nil && p.client != nil {
		p.client.CloseIdleConnections()
	}
}

func (p *Provider) Metadata() (Metadata, error) {
	if p == nil || p.verifier == nil {
		return Metadata{}, ErrNotConfigured
	}
	result := p.metadata
	result.AuthMethods = slices.Clone(result.AuthMethods)
	result.SigningAlgs = slices.Clone(result.SigningAlgs)
	return result, nil
}

func (p *Provider) Begin() (Authorization, error) {
	if p == nil || p.verifier == nil {
		return Authorization{}, ErrNotConfigured
	}
	value, err := randomValue()
	if err != nil {
		return Authorization{}, err
	}
	nonce, err := randomValue()
	if err != nil {
		return Authorization{}, err
	}
	state := State{Value: value, Nonce: nonce, Verifier: oauth2.GenerateVerifier(), Configuration: p.configuration}
	return Authorization{URL: p.oauth.AuthCodeURL(value, coreoidc.Nonce(nonce), oauth2.S256ChallengeOption(state.Verifier)), State: state}, nil
}

// Complete requires state already consumed atomically by the caller after its
// browser-binding and expiry checks. Reusing this State object is not replay
// protection; the package never owns the caller's cookie or persistence model.
func (p *Provider) Complete(ctx context.Context, callbackState, code string, state State) (*Assertion, error) {
	if p == nil || p.verifier == nil {
		return nil, ErrNotConfigured
	}
	if ctx == nil ||
		!canonicalValue(callbackState) ||
		!canonicalValue(state.Value) ||
		!canonicalValue(state.Nonce) ||
		!canonicalValue(state.Verifier) ||
		state.Configuration != p.configuration ||
		subtle.ConstantTimeCompare([]byte(callbackState), []byte(state.Value)) != 1 ||
		len(code) == 0 ||
		len(code) > 8192 {
		return nil, ErrInvalidState
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	ctx = coreoidc.ClientContext(ctx, p.client)
	tokens, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(state.Verifier))
	if err != nil {
		return nil, failed(ctx, ErrExchange)
	}
	raw, ok := tokens.Extra("id_token").(string)
	if !ok || len(raw) == 0 || int64(len(raw)) > p.maxBytes {
		return nil, ErrInvalidToken
	}
	token, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, failed(ctx, ErrInvalidToken)
	}
	if subtle.ConstantTimeCompare([]byte(token.Nonce), []byte(state.Nonce)) != 1 {
		return nil, ErrNonceMismatch
	}
	var claims json.RawMessage
	if token.Claims(&claims) != nil || !utf8.Valid(claims) || len(token.Subject) == 0 || len(token.Subject) > 4096 {
		return nil, ErrInvalidToken
	}
	var party struct {
		AuthorizedParty json.RawMessage `json:"azp"`
	}
	if json.Unmarshal(claims, &party) != nil {
		return nil, ErrInvalidToken
	}
	if len(party.AuthorizedParty) > 0 {
		var value string
		if json.Unmarshal(party.AuthorizedParty, &value) != nil || value != p.oauth.ClientID {
			return nil, ErrInvalidToken
		}
	} else if len(token.Audience) > 1 {
		return nil, ErrInvalidToken
	}
	if token.AccessTokenHash != "" && token.VerifyAccessToken(tokens.AccessToken) != nil {
		return nil, ErrInvalidToken
	}
	return &Assertion{Issuer: token.Issuer, ProviderIssuer: p.metadata.Issuer, Subject: token.Subject, Audience: slices.Clone(token.Audience), ExpiresAt: token.Expiry, IssuedAt: token.IssuedAt, claims: claims}, nil
}

func failed(ctx context.Context, category error) error {
	if ctx.Err() != nil {
		return errors.Join(category, ctx.Err())
	}
	return category
}
func randomValue() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func canonicalValue(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32
}
func httpsURL(value string, query bool) bool {
	if len(value) == 0 || len(value) > 8192 || !utf8.ValidString(value) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil && parsed.Fragment == "" && (query || parsed.RawQuery == "")
}
func normalizeScopes(values []string) ([]string, error) {
	if len(values) > 32 {
		return nil, ErrInvalidConfig
	}
	result := []string{"openid"}
	seen := map[string]bool{"openid": true}
	for _, value := range values {
		if len(value) == 0 || len(value) > 256 {
			return nil, ErrInvalidConfig
		}
		for _, b := range []byte(value) {
			if b < 0x21 || b > 0x7e || b == '"' || b == '\\' {
				return nil, ErrInvalidConfig
			}
		}
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result, nil
}
func acceptedAlgorithms(values []string) []string {
	result := []string{}
	for _, value := range values {
		switch value {
		case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA":
			if !slices.Contains(result, value) {
				result = append(result, value)
			}
		}
	}
	sort.Strings(result)
	return result
}
func chooseAuthMethod(requested AuthMethod, secret string, supported []string) (AuthMethod, oauth2.AuthStyle, error) {
	if requested == "" {
		if secret == "" {
			requested = PublicClient
		} else if slices.Contains(supported, string(ClientSecretBasic)) {
			requested = ClientSecretBasic
		} else {
			requested = ClientSecretPost
		}
	}
	if !slices.Contains(supported, string(requested)) {
		return "", 0, ErrUnsupportedAuthMethod
	}
	switch requested {
	case ClientSecretBasic:
		if secret != "" {
			return requested, oauth2.AuthStyleInHeader, nil
		}
	case ClientSecretPost:
		if secret != "" {
			return requested, oauth2.AuthStyleInParams, nil
		}
	case PublicClient:
		if secret == "" {
			return requested, oauth2.AuthStyleInParams, nil
		}
	}
	return "", 0, ErrUnsupportedAuthMethod
}
