package windows

import (
	"encoding/xml"
	"errors"
	"strings"
	"unicode"
)

const (
	PolicyNamespace      = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"
	PolicyAction         = PolicyNamespace + "/IPolicy/GetPolicies"
	PolicyResponseAction = PolicyAction + "Response"
	MaxPolicyBytes       = 128 << 10
	securityNS           = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	securityUtilityNS    = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	passwordTextType     = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"
)

var ErrPolicy = errors.New("invalid Windows enrollment policy request")
var ErrCredential = errors.New("invalid Windows enrollment credential")

// UsernameCredential is unverified wire input. It must be checked against a
// scoped enrollment credential store before a policy is returned, and checked
// again inside the certificate issuance transaction. Parsing grants no authority.
// Callers must not log its fields or the original SOAP message.
type UsernameCredential struct {
	Username string `json:"-" xml:"-" yaml:"-"`
	Password string `json:"-" xml:"-" yaml:"-"`
}

func (UsernameCredential) String() string   { return "[redacted Windows enrollment credential]" }
func (UsernameCredential) GoString() string { return "[redacted Windows enrollment credential]" }

type PolicyRequest struct {
	MessageID  string
	Credential UsernameCredential
}

// ParsePolicyRequest implements the MS-MDE2 OnPremise GetPolicies message. The
// federated-token and certificate-signature authentication flows are separate
// protocols and cannot fall through to UsernameToken authentication.
func ParsePolicyRequest(data []byte, expectedURL string) (*PolicyRequest, error) {
	message, err := parseSOAP(data, MaxPolicyBytes, xml.Name{Space: securityNS, Local: "Security"})
	if err != nil {
		return nil, err
	}
	if message.Action != PolicyAction {
		return nil, ErrPolicy
	}
	if !sameEnrollmentEndpoint(message.To, expectedURL) {
		return nil, ErrEndpoint
	}
	if !message.Body.is(PolicyNamespace, "GetPolicies") || !message.Body.container() || len(message.Body.Attrs) != 0 || len(message.Body.Children) != 2 {
		return nil, ErrPolicy
	}
	client, err := message.Body.one(PolicyNamespace, "client")
	if err != nil || !client.container() || len(client.Attrs) != 0 || len(client.Children) != 2 {
		return nil, ErrPolicy
	}
	for _, name := range []string{"lastUpdate", "preferredLanguage"} {
		e, err := client.one(PolicyNamespace, name)
		if err != nil || !policyNil(e) {
			return nil, ErrPolicy
		}
	}
	filter, err := message.Body.one(PolicyNamespace, "requestFilter")
	if err != nil || !policyNil(filter) {
		return nil, ErrPolicy
	}
	credential, err := parseUsernameCredential(message.Header)
	if err != nil {
		return nil, err
	}
	return &PolicyRequest{MessageID: message.MessageID, Credential: credential}, nil
}

func policyNil(e *xmlElement) bool {
	return e.container() && len(e.Children) == 0 && len(e.Attrs) == 1 && e.Attrs[0].Name == (xml.Name{Space: xsiNS, Local: "nil"}) && (e.Attrs[0].Value == "true" || e.Attrs[0].Value == "1")
}

func parseUsernameCredential(header *xmlElement) (UsernameCredential, error) {
	invalid := UsernameCredential{}
	security, err := header.one(securityNS, "Security")
	if err != nil || !security.container() || len(security.Children) != 1 {
		return invalid, ErrCredential
	}
	token, err := security.one(securityNS, "UsernameToken")
	if err != nil || !token.container() || len(token.Children) != 2 || len(token.Attrs) != 1 || token.Attrs[0].Name != (xml.Name{Space: securityUtilityNS, Local: "Id"}) {
		return invalid, ErrCredential
	}
	// MS-MDE2 publishes a fixed Id in its OnPremise examples. Treat any bounded
	// XML NCName as a label, never as a credential, identity or replay authority.
	id := token.Attrs[0].Value
	if len(id) == 0 || len(id) > 128 || !xmlNameStart.MatchString(id) || strings.Contains(id, ":") || strings.IndexFunc(id, unicode.IsSpace) >= 0 {
		return invalid, ErrCredential
	}
	// Reuse the XML name grammar to reject punctuation/control characters in Id.
	if _, err := parseXML([]byte("<"+id+"/>"), 132); err != nil {
		return invalid, ErrCredential
	}
	username, err := token.one(securityNS, "Username")
	if err != nil {
		return invalid, ErrCredential
	}
	name, err := username.plainText(512)
	if err != nil || name == "" || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return invalid, ErrCredential
	}
	password, err := token.one(securityNS, "Password")
	if err != nil || len(password.Children) != 0 || len(password.Attrs) != 1 || password.Attrs[0].Name.Local != "Type" || (password.Attrs[0].Name.Space != "" && password.Attrs[0].Name.Space != securityNS) || password.Attrs[0].Value != passwordTextType || len(password.Text) == 0 || len(password.Text) > 1024 {
		return invalid, ErrCredential
	}
	// Password text is exact, including leading/trailing whitespace. Never
	// normalize a secret to match a different credential. Normal XML entity and
	// line-ending processing is performed by the XML decoder before this point.
	return UsernameCredential{Username: name, Password: password.Text}, nil
}
