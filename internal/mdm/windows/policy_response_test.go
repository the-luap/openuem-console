package windows

import (
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// Decode with encoding/xml independently of the production parser and response
// structs, so namespace and schema-order regressions remain visible.
type policyWireNode struct {
	Name     xml.Name         `xml:""`
	Attrs    []xml.Attr       `xml:",any,attr"`
	Text     string           `xml:",chardata"`
	Children []policyWireNode `xml:",any"`
}

func (n *policyWireNode) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type contents struct {
		Text     string           `xml:",chardata"`
		Children []policyWireNode `xml:",any"`
	}
	var content contents
	if err := d.DecodeElement(&content, &start); err != nil {
		return err
	}
	n.Name, n.Attrs, n.Text, n.Children = start.Name, start.Attr, content.Text, content.Children
	return nil
}

func wireChild(t *testing.T, n *policyWireNode, space, name string) *policyWireNode {
	t.Helper()
	var found *policyWireNode
	for i := range n.Children {
		child := &n.Children[i]
		if child.Name.Local == name {
			if found != nil || child.Name.Space != space {
				t.Fatal("duplicate or incorrectly qualified wire child", name)
			}
			found = child
		}
	}
	if found == nil {
		t.Fatal("missing wire child", name)
	}
	return found
}

func policyWireChild(t *testing.T, n *policyWireNode, name string) *policyWireNode {
	t.Helper()
	return wireChild(t, n, PolicyNamespace, name)
}

func assertPolicySequence(t *testing.T, n *policyWireNode, names ...string) {
	t.Helper()
	var actual []string
	for _, child := range n.Children {
		if child.Name.Space != PolicyNamespace {
			t.Fatal("response child escaped policy namespace", child.Name.Local)
		}
		actual = append(actual, child.Name.Local)
	}
	if !slices.Equal(actual, names) {
		t.Fatalf("incorrect %s schema sequence: %v", n.Name.Local, actual)
	}
}

func assertPolicyNil(t *testing.T, n *policyWireNode) {
	t.Helper()
	var nilAttrs int
	for _, attr := range n.Attrs {
		if attr.Name == (xml.Name{Space: xsiNS, Local: "nil"}) && attr.Value == "true" {
			nilAttrs++
		} else if attr.Name.Space != "xmlns" {
			t.Fatal("unexpected nil field attribute")
		}
	}
	if nilAttrs != 1 || len(n.Children) != 0 || n.Text != "" {
		t.Fatal("nillable schema field was omitted or malformed", n.Name.Local)
	}
}

func TestPolicyResponseSchemaAndOIDReferences(t *testing.T) {
	a := EnrollmentAuthority{ID: "00000000-0000-0000-0000-000000000001", TenantID: 1, AuthorityOptions: authorityTestOptions()}
	der, private, err := generateAuthorityCertificate(a, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	clear(private)
	a.Certificate = der
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	a.ExpiresAt = cert.NotAfter
	data, err := buildPolicyResponse(discoveryTestID, a)
	if err != nil {
		t.Fatal(err)
	}
	var root policyWireNode
	if err := xml.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	header := wireChild(t, &root, soapNS, "Header")
	if wireChild(t, header, addressingNS, "Action").Text != PolicyResponseAction || wireChild(t, header, addressingNS, "RelatesTo").Text != discoveryTestID {
		t.Fatal("incorrect response action or correlation")
	}
	body := wireChild(t, &root, soapNS, "Body")
	response := policyWireChild(t, body, "GetPoliciesResponse")
	assertPolicySequence(t, response, "response", "cAs", "oIDs")
	assertPolicyNil(t, policyWireChild(t, response, "cAs"))
	metadata := policyWireChild(t, response, "response")
	assertPolicySequence(t, metadata, "policyID", "policyFriendlyName", "nextUpdateHours", "policiesNotChanged", "policies")
	if policyWireChild(t, metadata, "policyID").Text != "urn:uuid:"+a.ID || policyWireChild(t, metadata, "policiesNotChanged").Text != "false" {
		t.Fatal("response identity or full policy marker changed")
	}
	assertPolicyNil(t, policyWireChild(t, metadata, "nextUpdateHours"))
	policies := policyWireChild(t, metadata, "policies")
	assertPolicySequence(t, policies, "policy")
	policy := policyWireChild(t, policies, "policy")
	assertPolicySequence(t, policy, "policyOIDReference", "cAs", "attributes")
	assertPolicyNil(t, policyWireChild(t, policy, "cAs"))
	attrs := policyWireChild(t, policy, "attributes")
	assertPolicySequence(t, attrs, "commonName", "policySchema", "certificateValidity", "permission", "privateKeyAttributes", "revision", "supersededPolicies", "privateKeyFlags", "subjectNameFlags", "enrollmentFlags", "generalFlags", "hashAlgorithmOIDReference", "rARequirements", "keyArchivalAttributes", "extensions")
	if policyWireChild(t, attrs, "policySchema").Text != "3" {
		t.Fatal("MDE2 requires policy schema 3")
	}
	for _, name := range []string{"supersededPolicies", "privateKeyFlags", "subjectNameFlags", "enrollmentFlags", "generalFlags", "rARequirements", "keyArchivalAttributes", "extensions"} {
		assertPolicyNil(t, policyWireChild(t, attrs, name))
	}
	validity := policyWireChild(t, attrs, "certificateValidity")
	assertPolicySequence(t, validity, "validityPeriodSeconds", "renewalPeriodSeconds")
	if policyWireChild(t, validity, "validityPeriodSeconds").Text != fmt.Sprint(a.ValiditySeconds) || policyWireChild(t, validity, "renewalPeriodSeconds").Text != fmt.Sprint(a.RenewalSeconds) {
		t.Fatal("policy lifetime differs from issuer configuration")
	}
	permission := policyWireChild(t, attrs, "permission")
	assertPolicySequence(t, permission, "enroll", "autoEnroll")
	if policyWireChild(t, permission, "enroll").Text != "true" || policyWireChild(t, permission, "autoEnroll").Text != "false" {
		t.Fatal("policy advertised auto-enrollment")
	}
	key := policyWireChild(t, attrs, "privateKeyAttributes")
	assertPolicySequence(t, key, "minimalKeyLength", "keySpec", "keyUsageProperty", "permissions", "algorithmOIDReference", "cryptoProviders")
	if policyWireChild(t, key, "minimalKeyLength").Text != fmt.Sprint(a.MinimumKeyBits) {
		t.Fatal("key floor differs from issuer policy")
	}
	for _, name := range []string{"keySpec", "keyUsageProperty", "permissions", "cryptoProviders"} {
		assertPolicyNil(t, policyWireChild(t, key, name))
	}
	revision := policyWireChild(t, attrs, "revision")
	assertPolicySequence(t, revision, "majorRevision", "minorRevision")
	if policyWireChild(t, revision, "majorRevision").Text != "1" || policyWireChild(t, revision, "minorRevision").Text != "0" {
		t.Fatal("incorrect immutable policy revision")
	}
	oids := policyWireChild(t, response, "oIDs")
	assertPolicySequence(t, oids, "oID", "oID", "oID")
	type oidValue struct{ value, group string }
	references := map[string]oidValue{}
	for i := range oids.Children {
		oid := &oids.Children[i]
		assertPolicySequence(t, oid, "value", "group", "oIDReferenceID", "defaultName")
		id := policyWireChild(t, oid, "oIDReferenceID").Text
		if _, ok := references[id]; ok {
			t.Fatal("duplicate OID reference")
		}
		references[id] = oidValue{policyWireChild(t, oid, "value").Text, policyWireChild(t, oid, "group").Text}
		if policyWireChild(t, oid, "defaultName").Text == "" {
			t.Fatal("OID name omitted")
		}
	}
	if references[policyWireChild(t, policy, "policyOIDReference").Text] != (oidValue{"2.25.1", "9"}) || references[policyWireChild(t, attrs, "hashAlgorithmOIDReference").Text] != (oidValue{"2.16.840.1.101.3.4.2.1", "1"}) || references[policyWireChild(t, key, "algorithmOIDReference").Text] != (oidValue{"1.2.840.113549.1.1.1", "3"}) {
		t.Fatal("policy/hash/public-key OID reference or group is incorrect")
	}
	for _, absent := range []string{a.Organization, "Attestation", "PrivateKeyContainer", "BinarySecurityToken", "certificate>"} {
		if strings.Contains(string(data), absent) {
			t.Fatal("policy included unrequested identity, key or capabilities")
		}
	}
	if got, err := buildPolicyResponse("invalid", a); !errors.Is(err, ErrPolicy) || got != nil {
		t.Fatal("invalid response correlation admitted")
	}
	a.MinimumKeyBits = 1024
	if got, err := buildPolicyResponse(discoveryTestID, a); !errors.Is(err, ErrAuthority) || got != nil {
		t.Fatal("invalid issuer policy admitted")
	}
}
