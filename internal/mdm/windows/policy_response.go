package windows

import (
	"context"
	"encoding/xml"
	"math/big"

	"github.com/google/uuid"
)

// All required nillable elements are emitted in MS-XCEP schema order. These
// models are private: callers receive a policy only through credential and CA
// authorization in EnrollmentPolicyResponse.
type policyNull struct {
	Nil bool `xml:"http://www.w3.org/2001/XMLSchema-instance nil,attr"`
}

type policyResponse struct {
	XMLName  xml.Name           `xml:"http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy GetPoliciesResponse"`
	Response policyResponseData `xml:"response"`
	CAs      policyNull         `xml:"cAs"`
	OIDs     []policyOID        `xml:"oIDs>oID"`
}

type policyResponseData struct {
	ID              string              `xml:"policyID"`
	FriendlyName    string              `xml:"policyFriendlyName"`
	NextUpdateHours policyNull          `xml:"nextUpdateHours"`
	NotChanged      bool                `xml:"policiesNotChanged"`
	Policies        []certificatePolicy `xml:"policies>policy"`
}

type certificatePolicy struct {
	OIDReference int              `xml:"policyOIDReference"`
	CAs          policyNull       `xml:"cAs"`
	Attributes   policyAttributes `xml:"attributes"`
}

type policyAttributes struct {
	CommonName       string           `xml:"commonName"`
	Schema           int              `xml:"policySchema"`
	Validity         policyValidity   `xml:"certificateValidity"`
	Permission       policyPermission `xml:"permission"`
	PrivateKey       policyPrivateKey `xml:"privateKeyAttributes"`
	Revision         policyRevision   `xml:"revision"`
	Superseded       policyNull       `xml:"supersededPolicies"`
	PrivateKeyFlags  policyNull       `xml:"privateKeyFlags"`
	SubjectNameFlags policyNull       `xml:"subjectNameFlags"`
	EnrollmentFlags  policyNull       `xml:"enrollmentFlags"`
	GeneralFlags     policyNull       `xml:"generalFlags"`
	HashOIDReference int              `xml:"hashAlgorithmOIDReference"`
	RARequirements   policyNull       `xml:"rARequirements"`
	KeyArchival      policyNull       `xml:"keyArchivalAttributes"`
	Extensions       policyNull       `xml:"extensions"`
}

type policyValidity struct {
	Validity int64 `xml:"validityPeriodSeconds"`
	Renewal  int64 `xml:"renewalPeriodSeconds"`
}

type policyPermission struct {
	Enroll     bool `xml:"enroll"`
	AutoEnroll bool `xml:"autoEnroll"`
}

type policyPrivateKey struct {
	MinimumBits           int        `xml:"minimalKeyLength"`
	KeySpec               policyNull `xml:"keySpec"`
	KeyUsage              policyNull `xml:"keyUsageProperty"`
	Permissions           policyNull `xml:"permissions"`
	AlgorithmOIDReference int        `xml:"algorithmOIDReference"`
	Providers             policyNull `xml:"cryptoProviders"`
}

type policyRevision struct {
	Major int `xml:"majorRevision"`
	Minor int `xml:"minorRevision"`
}

type policyOID struct {
	Value     string `xml:"value"`
	Group     int    `xml:"group"`
	Reference int    `xml:"oIDReferenceID"`
	Name      string `xml:"defaultName"`
}

func buildPolicyResponse(messageID string, a EnrollmentAuthority) ([]byte, error) {
	if !validMessageID(messageID) {
		return nil, ErrPolicy
	}
	if _, err := parseAuthorityCertificate(a); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(a.ID)
	if err != nil {
		return nil, ErrAuthority
	}
	// ITU-T X.667 maps a UUID's unsigned 128-bit integer under the 2.25 arc.
	// The enrollment object, SHA-256 hash and RSA public key have distinct IDs
	// and MS-XCEP groups 9, 1 and 3, respectively.
	policyObject := "2.25." + new(big.Int).SetBytes(id[:]).String()
	nilValue := policyNull{Nil: true}
	attributes := policyAttributes{
		CommonName: "OpenUEMWindows-" + a.ID, Schema: 3,
		Validity:   policyValidity{Validity: a.ValiditySeconds, Renewal: a.RenewalSeconds},
		Permission: policyPermission{Enroll: true, AutoEnroll: false},
		PrivateKey: policyPrivateKey{MinimumBits: a.MinimumKeyBits, KeySpec: nilValue, KeyUsage: nilValue, Permissions: nilValue, AlgorithmOIDReference: 2, Providers: nilValue},
		Revision:   policyRevision{Major: 1, Minor: 0}, Superseded: nilValue,
		PrivateKeyFlags: nilValue, SubjectNameFlags: nilValue, EnrollmentFlags: nilValue, GeneralFlags: nilValue,
		HashOIDReference: 1, RARequirements: nilValue, KeyArchival: nilValue, Extensions: nilValue,
	}
	return soapResponse(PolicyResponseAction, messageID, policyResponse{
		Response: policyResponseData{ID: "urn:uuid:" + a.ID, FriendlyName: "OpenUEM Windows enrollment", NextUpdateHours: nilValue, NotChanged: false,
			Policies: []certificatePolicy{{OIDReference: 0, CAs: nilValue, Attributes: attributes}}},
		CAs: nilValue,
		OIDs: []policyOID{{Value: policyObject, Group: 9, Reference: 0, Name: "OpenUEM Windows enrollment"},
			{Value: "2.16.840.1.101.3.4.2.1", Group: 1, Reference: 1, Name: "SHA256"},
			{Value: "1.2.840.113549.1.1.1", Group: 3, Reference: 2, Name: "RSA"}},
	})
}

// EnrollmentPolicyResponse authorizes the credential, current issuer permissions
// and live scope, then verifies that the organization's CA can issue the stated
// certificate policy. The response is returned only after its audit commits. A
// policy read never consumes an invitation or authorizes subsequent issuance.
func (s *Store) EnrollmentPolicyResponse(ctx context.Context, request *PolicyRequest) ([]byte, error) {
	if request == nil || !validMessageID(request.MessageID) {
		return nil, ErrPolicy
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	i, err := s.authorizeEnrollmentCredential(ctx, tx, request.Credential, false)
	if err != nil {
		return nil, err
	}
	a, err := s.enrollmentAuthority(ctx, tx, i.TenantID)
	if err != nil {
		return nil, err
	}
	response, err := buildPolicyResponse(request.MessageID, a.metadata)
	if err != nil {
		return nil, err
	}
	if err := auditInvitation(ctx, tx, *i, "windows-enrollment", "policy.read"); err != nil {
		return nil, err
	}
	if err := activeEnrollmentInvitation(ctx, tx, i.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return response, nil
}
