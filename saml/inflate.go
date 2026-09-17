package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"io"
)

// InflateLimited raw-DEFLATE-decompresses data (as used by the SAML
// HTTP-Redirect binding, RFC 1951 with no zlib/gzip wrapper) and returns
// the result, refusing to produce more than maxBytes of output.
//
// This exists because a DEFLATE stream's decompressed size is not bounded
// by its compressed size in any way a decoder can check up front — a
// few-KB compressed payload can expand to gigabytes (GHSA-5mqj-xc49-246p
// is exactly this class of issue). InflateLimited enforces the cap by
// reading through the limit and erroring the moment it would be exceeded,
// rather than decompressing fully and checking len() afterward, so the
// large intermediate buffer is never allocated.
//
// maxBytes <= 0 uses DefaultMaxInflatedBytes.
func InflateLimited(data []byte, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxInflatedBytes
	}
	fr := flate.NewReader(bytes.NewReader(data))
	defer fr.Close()

	// Read exactly one byte past the limit so a payload that inflates to
	// precisely maxBytes is accepted, and anything larger is caught
	// without buffering it all first.
	limited := io.LimitReader(fr, maxBytes+1)
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("saml: inflate: %w", err)
	}
	if int64(len(out)) > maxBytes {
		return nil, fmt.Errorf("%w: inflated payload exceeds %d bytes", ErrResponseTooLarge, maxBytes)
	}
	return out, nil
}

// DecodeRedirectMessage base64-decodes and then safely inflates a
// SAML HTTP-Redirect-binding query parameter value (SAMLRequest or
// SAMLResponse when SAMLEncoding is absent or
// "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE", which is
// the only encoding the binding defines). maxBytes bounds the inflated
// output; <= 0 uses DefaultMaxInflatedBytes.
func DecodeRedirectMessage(raw string, maxBytes int64) ([]byte, error) {
	compressed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("saml: decode base64: %w", err)
	}
	return InflateLimited(compressed, maxBytes)
}
