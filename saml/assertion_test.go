package saml

import (
	"context"
	"errors"
	"net/url"
	"testing"

	crewjamsaml "github.com/crewjam/saml"
)

// attr builds one <Attribute> element as crewjam would hand it over.
func attr(name, friendly string, values ...string) crewjamsaml.Attribute {
	a := crewjamsaml.Attribute{Name: name, FriendlyName: friendly}
	for _, v := range values {
		a.Values = append(a.Values, crewjamsaml.AttributeValue{Value: v})
	}
	return a
}

func crewjamAssertion(statements ...[]crewjamsaml.Attribute) *crewjamsaml.Assertion {
	a := &crewjamsaml.Assertion{}
	for _, attrs := range statements {
		a.AttributeStatements = append(a.AttributeStatements, crewjamsaml.AttributeStatement{Attributes: attrs})
	}
	return a
}

// AttributesByName exists so a caller can map IdP claims onto its own fields from
// the Name the IdP actually declared. Attributes cannot serve that purpose: it
// indexes by Name AND FriendlyName, so after a collision the original source is
// gone.
func TestAssertionFromCrewjam_AttributesByNameIndexesTheNameOnly(t *testing.T) {
	a, err := assertionFromCrewjam(crewjamAssertion([]crewjamsaml.Attribute{
		attr("urn:oid:1.2.3", "mail", "alice@corp.example"),
	}), false)
	if err != nil {
		t.Fatalf("assertionFromCrewjam: %v", err)
	}

	if got := a.AttributesByName["urn:oid:1.2.3"]; len(got) != 1 || got[0] != "alice@corp.example" {
		t.Errorf("AttributesByName by Name = %v", got)
	}
	if _, present := a.AttributesByName["mail"]; present {
		t.Error("AttributesByName indexed a FriendlyName; a caller cannot tell a real Name from a friendly one after a collision")
	}
	// The old map keeps its behaviour, both keys.
	if len(a.Attributes["urn:oid:1.2.3"]) != 1 || len(a.Attributes["mail"]) != 1 {
		t.Errorf("Attributes lost a key: %v", a.Attributes)
	}
}

// The case the new map exists for: attribute one is Name=email / FriendlyName=mail,
// attribute two is Name=mail. In the merged map the second attribute's value is
// indistinguishable from the first attribute's friendly-name alias; the by-name
// map still separates them.
func TestAssertionFromCrewjam_CollidingNameAndFriendlyNameStayRecoverable(t *testing.T) {
	a, err := assertionFromCrewjam(crewjamAssertion([]crewjamsaml.Attribute{
		attr("email", "mail", "from-the-email-attribute"),
		attr("mail", "", "from-the-mail-attribute"),
	}), false)
	if err != nil {
		t.Fatalf("assertionFromCrewjam: %v", err)
	}

	// The merged map cannot tell them apart — that is inherent to its shape, and
	// it is why the by-name map exists rather than a filter over this one.
	if got := a.Attributes["mail"]; len(got) != 2 {
		t.Fatalf("merged Attributes[mail] = %v, want both values (the behaviour callers already depend on)", got)
	}
	if got := a.AttributesByName["email"]; len(got) != 1 || got[0] != "from-the-email-attribute" {
		t.Errorf("AttributesByName[email] = %v", got)
	}
	if got := a.AttributesByName["mail"]; len(got) != 1 || got[0] != "from-the-mail-attribute" {
		t.Errorf("AttributesByName[mail] = %v", got)
	}
}

func TestAssertionFromCrewjam_RepeatedNameMergesInOrder(t *testing.T) {
	a, err := assertionFromCrewjam(crewjamAssertion([]crewjamsaml.Attribute{
		attr("groups", "memberOf", "one", "two"),
		attr("groups", "", "three"),
	}), false)
	if err != nil {
		t.Fatalf("assertionFromCrewjam: %v", err)
	}
	got := a.AttributesByName["groups"]
	want := []string{"one", "two", "three"}
	if len(got) != len(want) {
		t.Fatalf("AttributesByName[groups] = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AttributesByName[groups] = %v, want %v", got, want)
		}
	}
}

// An attribute whose Name and FriendlyName are the same string is indexed once,
// not twice — the same rule dedupeKeys applies to the merged map.
func TestAssertionFromCrewjam_NameEqualToFriendlyNameIndexesOnce(t *testing.T) {
	a, err := assertionFromCrewjam(crewjamAssertion([]crewjamsaml.Attribute{
		attr("groups", "groups", "eng"),
	}), false)
	if err != nil {
		t.Fatalf("assertionFromCrewjam: %v", err)
	}
	if got := a.AttributesByName["groups"]; len(got) != 1 {
		t.Errorf("AttributesByName[groups] = %v, want one value", got)
	}
	if got := a.Attributes["groups"]; len(got) != 1 {
		t.Errorf("Attributes[groups] = %v, want one value", got)
	}
}

// Values are handed over exactly as the IdP sent them, empty ones included: an
// empty claim is a claim, and whether it means anything is the caller's mapping
// rule.
func TestAssertionFromCrewjam_PreservesEmptyValues(t *testing.T) {
	a, err := assertionFromCrewjam(crewjamAssertion([]crewjamsaml.Attribute{
		attr("upn", "", "", "alice@corp.example"),
	}), false)
	if err != nil {
		t.Fatalf("assertionFromCrewjam: %v", err)
	}
	got := a.AttributesByName["upn"]
	if len(got) != 2 || got[0] != "" || got[1] != "alice@corp.example" {
		t.Fatalf("AttributesByName[upn] = %q, want the empty value kept in place", got)
	}
}

func TestAssertionFromCrewjam_AccumulatesAcrossStatements(t *testing.T) {
	a, err := assertionFromCrewjam(crewjamAssertion(
		[]crewjamsaml.Attribute{attr("groups", "", "first")},
		[]crewjamsaml.Attribute{attr("groups", "", "second")},
	), false)
	if err != nil {
		t.Fatalf("assertionFromCrewjam: %v", err)
	}
	got := a.AttributesByName["groups"]
	if len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("AttributesByName[groups] = %v, want both statements in order", got)
	}
}

// An attribute with no Name has no name to index under. It must not appear under
// an empty key, and it must not panic.
func TestAssertionFromCrewjam_AttributeWithoutANameIsNotIndexed(t *testing.T) {
	a, err := assertionFromCrewjam(crewjamAssertion([]crewjamsaml.Attribute{
		attr("", "just-a-friendly-name", "value"),
	}), false)
	if err != nil {
		t.Fatalf("assertionFromCrewjam: %v", err)
	}
	if _, present := a.AttributesByName[""]; present {
		t.Error("an empty key was indexed")
	}
	if len(a.AttributesByName) != 0 {
		t.Errorf("AttributesByName = %v, want nothing indexed", a.AttributesByName)
	}
}

// The two maps must not share storage: a caller that edits one (or appends to it)
// must not be able to corrupt the other, which is the failure a shared backing
// array would produce.
func TestAssertionFromCrewjam_MapsDoNotShareSliceStorage(t *testing.T) {
	a, err := assertionFromCrewjam(crewjamAssertion([]crewjamsaml.Attribute{
		attr("groups", "memberOf", "one"),
	}), false)
	if err != nil {
		t.Fatalf("assertionFromCrewjam: %v", err)
	}

	a.AttributesByName["groups"][0] = "tampered-byname"
	if a.Attributes["groups"][0] == "tampered-byname" {
		t.Error("Attributes and AttributesByName share a backing array")
	}
	a.Attributes["groups"][0] = "tampered-name"
	if a.Attributes["memberOf"][0] == "tampered-name" {
		t.Error("the two keys of the merged map share a backing array")
	}
	if a.AttributesByName["groups"][0] != "tampered-byname" {
		t.Error("editing the merged map changed the by-name map")
	}
}

// StrictAttributes still refuses a duplicate Name, and the new map does not
// change that decision.
func TestAssertionFromCrewjam_StrictAttributesStillRefusesDuplicates(t *testing.T) {
	_, err := assertionFromCrewjam(crewjamAssertion([]crewjamsaml.Attribute{
		attr("mail", "", "a"),
		attr("mail", "", "b"),
	}), true)
	if !errors.Is(err, ErrDuplicateAttribute) {
		t.Fatalf("strict duplicate = %v, want ErrDuplicateAttribute", err)
	}
}

// The new field must be populated by the REAL validation path, not only by the
// conversion function: a caller maps claims off a response it validated, and a
// field that exists only when the converter is called directly would be empty in
// production.
func TestValidateResponse_PopulatesAttributesByName(t *testing.T) {
	sp := newTestSPMaterial(t, "byname")
	idp := newTestIdP(t, sp.entityID, sp.acsURL, sp.cert)
	idp.customAttributes = []crewjamsaml.Attribute{
		attr("urn:oid:1.2.3", "mail", "alice@corp.example"),
		attr("groups", "", "engineering", "sso-test"),
	}
	p := newTestProvider(t, sp, idp.idp.Metadata(), func(c *Config) { c.AllowIDPInitiated = true })

	raw := idp.idpInitiatedResponse(t)
	assertion, err := p.ValidateResponseXML(context.Background(), raw, url.URL{}, nil)
	if err != nil {
		t.Fatalf("ValidateResponseXML: %v", err)
	}

	if got := assertion.AttributesByName["urn:oid:1.2.3"]; len(got) != 1 || got[0] != "alice@corp.example" {
		t.Errorf("AttributesByName[urn:oid:1.2.3] = %v", got)
	}
	if got := assertion.AttributesByName["groups"]; len(got) != 2 {
		t.Errorf("AttributesByName[groups] = %v, want both values", got)
	}
	// And the friendly name is still only in the merged map.
	if _, present := assertion.AttributesByName["mail"]; present {
		t.Error("the real path indexed a FriendlyName")
	}
}
