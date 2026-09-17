package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"

	crewjamsaml "github.com/crewjam/saml"
)

// deflate raw-DEFLATE-compresses data (no zlib/gzip wrapper), matching
// what the SAML HTTP-Redirect binding uses.
func deflate(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return buf.Bytes()
}

func TestInflateLimited_RoundTrip(t *testing.T) {
	original := []byte("<samlp:Response>hello world</samlp:Response>")
	compressed := deflate(t, original)

	out, err := InflateLimited(compressed, 0)
	if err != nil {
		t.Fatalf("InflateLimited: %v", err)
	}
	if !bytes.Equal(out, original) {
		t.Fatalf("InflateLimited output = %q, want %q", out, original)
	}
}

// TestInflateLimited_DecompressionBomb is the GHSA-5mqj-xc49-246p
// scenario: a small, highly-compressible payload (a huge run of one byte
// compresses to almost nothing) must be refused once its decompressed
// size would exceed the cap, and the compressed input here is itself
// tiny — this proves the cap is enforced on the OUTPUT, not inferred from
// the input size.
func TestInflateLimited_DecompressionBomb(t *testing.T) {
	const decompressedSize = 50 * 1024 * 1024 // 50MB
	bomb := bytes.Repeat([]byte{'A'}, decompressedSize)
	compressed := deflate(t, bomb)

	if len(compressed) > 1<<16 {
		t.Fatalf("test setup: compressed bomb is %d bytes, expected it to compress to well under 64KB", len(compressed))
	}
	t.Logf("compressed %d bytes -> %d bytes (%.0fx)", decompressedSize, len(compressed), float64(decompressedSize)/float64(len(compressed)))

	const limit = 1 << 20 // 1MiB
	_, err := InflateLimited(compressed, limit)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
}

func TestInflateLimited_ExactlyAtLimit(t *testing.T) {
	data := bytes.Repeat([]byte{'x'}, 1000)
	compressed := deflate(t, data)

	if _, err := InflateLimited(compressed, 1000); err != nil {
		t.Fatalf("payload of exactly the limit must be accepted: %v", err)
	}
	if _, err := InflateLimited(compressed, 999); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("payload one byte over the limit: err = %v, want ErrResponseTooLarge", err)
	}
}

func TestInflateLimited_CorruptInput(t *testing.T) {
	_, err := InflateLimited([]byte{0xff, 0xff, 0xff, 0xff}, 0)
	if err == nil {
		t.Fatal("expected an error decompressing garbage, got nil")
	}
}

func TestDecodeRedirectMessage(t *testing.T) {
	original := []byte("<samlp:Response>redirect binding</samlp:Response>")
	compressed := deflate(t, original)
	encoded := base64.StdEncoding.EncodeToString(compressed)

	out, err := DecodeRedirectMessage(encoded, 0)
	if err != nil {
		t.Fatalf("DecodeRedirectMessage: %v", err)
	}
	if !bytes.Equal(out, original) {
		t.Fatalf("got %q, want %q", out, original)
	}

	if _, err := DecodeRedirectMessage("not valid base64!!", 0); err == nil {
		t.Fatal("expected a base64 decode error, got nil")
	}
}

// TestProvider_ValidateRedirectResponse_DecompressionBomb exercises the
// same defense through the Provider entry point a caller actually uses
// for a redirect-bound message.
func TestProvider_ValidateRedirectResponse_DecompressionBomb(t *testing.T) {
	sp := newTestSPMaterial(t, "redirectbomb")
	idpMeta := &crewjamsaml.EntityDescriptor{EntityID: "https://idp.example.com/saml/metadata"}
	p := newTestProvider(t, sp, idpMeta, func(c *Config) {
		c.MaxInflatedBytes = 1 << 20 // 1MiB
	})

	bomb := bytes.Repeat([]byte{'A'}, 50*1024*1024)
	compressed := deflate(t, bomb)
	encoded := base64.StdEncoding.EncodeToString(compressed)

	acsURL, err := url.Parse(sp.acsURL)
	if err != nil {
		t.Fatalf("parse acs url: %v", err)
	}
	_, err = p.ValidateRedirectResponse(context.Background(), encoded, *acsURL, nil)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
}
