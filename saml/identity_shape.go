package saml

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
)

// Validate plaintext identity shape before dependency decoding. These checks
// grant no trust: original signature, condition and replay validation still run.
// Encrypted assertions are not visible here and need a dependency-level fix.
func validatePlaintextIdentityShape(raw []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	var stack []xml.Name
	issuers, subjects, names := 0, 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: identity XML cannot be decoded", ErrMalformedResponse)
		}
		switch element := token.(type) {
		case xml.StartElement:
			stack = append(stack, element.Name)
			if len(stack) == 2 && element.Name == (xml.Name{Space: samlAssertionNS, Local: "Assertion"}) {
				issuers, subjects, names = 0, 0, 0
			}
			if len(stack) < 3 || stack[1] != (xml.Name{Space: samlAssertionNS, Local: "Assertion"}) {
				continue
			}
			if len(stack) == 3 && element.Name.Local == "Issuer" {
				issuers++
				if element.Name.Space != samlAssertionNS || issuers != 1 {
					return fmt.Errorf("%w: assertion Issuer namespace or count", ErrMalformedResponse)
				}
			}
			if len(stack) == 3 && element.Name.Local == "Subject" {
				subjects++
				if element.Name.Space != samlAssertionNS || subjects != 1 {
					return fmt.Errorf("%w: assertion Subject namespace or count", ErrMalformedResponse)
				}
			}
			if len(stack) == 4 && stack[2].Local == "Subject" && element.Name.Local == "NameID" {
				names++
				if element.Name.Space != samlAssertionNS || names != 1 {
					return fmt.Errorf("%w: subject NameID namespace or count", ErrMalformedResponse)
				}
			}
		case xml.EndElement:
			if len(stack) == 2 && stack[1] == (xml.Name{Space: samlAssertionNS, Local: "Assertion"}) && issuers != 1 {
				return fmt.Errorf("%w: assertion Issuer required", ErrMalformedResponse)
			}
			stack = stack[:len(stack)-1]
		}
	}
}
