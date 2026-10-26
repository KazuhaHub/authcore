package saml

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"net/url"

	crewjamsaml "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

func authnSigningMethod(config Config) (string, error) {
	required := config.SignAuthnRequests
	for _, descriptor := range config.IDPMetadata.IDPSSODescriptors {
		required = required || descriptor.WantAuthnRequestsSigned != nil && *descriptor.WantAuthnRequestsSigned
	}
	if !required {
		return "", nil
	}
	invalid := errors.New("saml: signed AuthnRequest requires a matching RSA or ECDSA SHA-256 key pair")
	if config.Key == nil || config.Certificate == nil {
		return "", invalid
	}
	var method string
	switch key := config.Key.(type) {
	case *rsa.PrivateKey:
		if key == nil || key.N == nil || key.D == nil || key.E < 3 || len(key.Primes) < 2 || key.N.BitLen() < 2048 || key.Validate() != nil {
			return "", invalid
		}
		method = dsig.RSASHA256SignatureMethod
	case *ecdsa.PrivateKey:
		if key == nil || key.Curve == nil || key.D == nil || key.X == nil || key.Y == nil || key.Curve.Params().BitSize < 256 || key.D.Sign() <= 0 || key.D.Cmp(key.Curve.Params().N) >= 0 || !key.Curve.IsOnCurve(key.X, key.Y) {
			return "", invalid
		}
		method = dsig.ECDSASHA256SignatureMethod
	default:
		return "", invalid
	}
	certificate, err := x509.ParseCertificate(config.Certificate.Raw)
	if err != nil {
		return "", invalid
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(config.Key.Public())
	if err != nil {
		return "", invalid
	}
	certPublic, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil || !bytes.Equal(keyPublic, certPublic) {
		return "", invalid
	}
	return method, nil
}

func authnEndpoint(raw, relay string) (*url.URL, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Scheme != "https" && endpoint.Scheme != "http" || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" || len(relay) > 80 {
		return nil, errors.New("saml: invalid AuthnRequest endpoint or RelayState")
	}
	query, err := url.ParseQuery(endpoint.RawQuery)
	if err != nil {
		return nil, errors.New("saml: invalid AuthnRequest endpoint query")
	}
	for _, name := range []string{"SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature"} {
		if _, exists := query[name]; exists {
			return nil, errors.New("saml: AuthnRequest endpoint contains a reserved binding parameter")
		}
	}
	return endpoint, nil
}

func authnRedirect(request *crewjamsaml.AuthnRequest, sp *crewjamsaml.ServiceProvider, endpoint *url.URL, relay string) (*url.URL, error) {
	// Let crewjam serialize and DEFLATE the XML, but keep endpoint query fields
	// outside the signed octets required by SAML Bindings section 3.4.4.1.
	unsigned := *sp
	unsigned.SignatureMethod = ""
	redirect, err := request.Redirect(url.QueryEscape(relay), &unsigned)
	if err != nil || sp.SignatureMethod == "" {
		return redirect, err
	}
	query := "SAMLRequest=" + url.QueryEscape(redirect.Query().Get("SAMLRequest"))
	if relay != "" {
		query += "&RelayState=" + url.QueryEscape(relay)
	}
	query += "&SigAlg=" + url.QueryEscape(sp.SignatureMethod)
	signing, err := crewjamsaml.GetSigningContext(sp)
	if err != nil {
		return nil, err
	}
	signature, err := signing.SignString(query)
	if err != nil {
		return nil, err
	}
	if key, ok := sp.Key.(*ecdsa.PrivateKey); ok {
		// crypto.Signer emits ASN.1; XMLDSig ECDSA requires fixed-width r || s.
		var parts struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(signature, &parts)
		order := key.Curve.Params().N
		if err != nil || len(rest) != 0 || parts.R == nil || parts.S == nil || parts.R.Sign() <= 0 || parts.S.Sign() <= 0 || parts.R.Cmp(order) >= 0 || parts.S.Cmp(order) >= 0 {
			return nil, errors.New("saml: invalid ECDSA signing result")
		}
		width := (order.BitLen() + 7) / 8
		signature = make([]byte, 2*width)
		parts.R.FillBytes(signature[:width])
		parts.S.FillBytes(signature[width:])
	}
	query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))
	if endpoint.RawQuery != "" {
		query = endpoint.RawQuery + "&" + query
	}
	redirect.RawQuery = query
	return redirect, nil
}
