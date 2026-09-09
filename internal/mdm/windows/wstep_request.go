package windows

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	wstepNS                   = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"
	trustNS                   = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
	contextNS                 = "http://schemas.xmlsoap.org/ws/2006/12/authorization"
	deviceTokenType           = "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken"
	provisionTokenType        = "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc"
	binaryEncodingType        = securityNS + "#base64binary"
	WSTEPAction               = wstepNS + "/RST/wstep"
	WSTEPResponseAction       = wstepNS + "/RSTRC/wstep"
	MaxWSTEPBytes             = 128 << 10
	MaxEnrollmentCSRBytes     = 16 << 10
	maxEnrollmentContextItems = 64
	maxEnrollmentContextBytes = 16 << 10
)

var ErrWSTEP = errors.New("invalid Windows certificate enrollment request")
var ErrCSR = errors.New("invalid Windows enrollment certificate signing request")

// EnrollmentContextItem is an untrusted device hint. Even hardware identifiers,
// account names and attestation-looking fields do not establish device identity
// or organization membership. Only MAC and IMEI may occur more than once.
type EnrollmentContextItem struct{ Name, Value string }

type WSTEPRequest struct {
	MessageID  string
	Credential UsernameCredential      `json:"-" xml:"-" yaml:"-"`
	CSRDER     []byte                  `json:"-" xml:"-" yaml:"-"`
	Context    []EnrollmentContextItem `json:"-" xml:"-" yaml:"-"`
}

func (WSTEPRequest) String() string   { return "[protected Windows enrollment request]" }
func (WSTEPRequest) GoString() string { return "[protected Windows enrollment request]" }

// ParseWSTEPRequest accepts the initial MS-MDE2 OnPremise Issue operation.
// Renewal (PKCS#7), federated tokens and certificate-authenticated enrollment
// must use their own verification flows, never fall through to initial issuance.
func ParseWSTEPRequest(data []byte, expectedURL string) (*WSTEPRequest, error) {
	message, err := parseSOAP(data, MaxWSTEPBytes, xml.Name{Space: securityNS, Local: "Security"})
	if err != nil {
		return nil, err
	}
	if message.Action != WSTEPAction {
		return nil, ErrWSTEP
	}
	if !sameEnrollmentEndpoint(message.To, expectedURL) {
		return nil, ErrEndpoint
	}
	body := message.Body
	if !body.is(trustNS, "RequestSecurityToken") || !body.container() || len(body.Attrs) != 0 || len(body.Children) != 4 {
		return nil, ErrWSTEP
	}
	for name, expected := range map[string]string{"TokenType": deviceTokenType, "RequestType": trustNS + "/Issue"} {
		e, err := body.one(trustNS, name)
		if err != nil {
			return nil, ErrWSTEP
		}
		value, err := e.plainText(256)
		if err != nil || value != expected {
			return nil, ErrWSTEP
		}
	}
	token, err := body.one(securityNS, "BinarySecurityToken")
	if err != nil || len(token.Children) != 0 || len(token.Attrs) != 2 {
		return nil, ErrWSTEP
	}
	for _, attr := range token.Attrs {
		if attr.Name.Space != "" {
			return nil, ErrWSTEP
		}
		switch attr.Name.Local {
		case "ValueType":
			if attr.Value != wstepNS+"#PKCS10" {
				return nil, ErrWSTEP
			}
		case "EncodingType":
			if attr.Value != binaryEncodingType {
				return nil, ErrWSTEP
			}
		default:
			return nil, ErrWSTEP
		}
	}
	encoded := strings.Map(func(r rune) rune {
		if strings.ContainsRune(" \t\r\n", r) {
			return -1
		}
		return r
	}, token.Text)
	if len(encoded) == 0 || len(encoded) > base64.StdEncoding.EncodedLen(MaxEnrollmentCSRBytes) {
		return nil, ErrCSR
	}
	der, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(der) > MaxEnrollmentCSRBytes || base64.StdEncoding.EncodeToString(der) != encoded {
		return nil, ErrCSR
	}
	context, err := body.one(contextNS, "AdditionalContext")
	if err != nil || !context.container() || len(context.Attrs) != 0 || len(context.Children) > maxEnrollmentContextItems {
		return nil, ErrWSTEP
	}
	items := make([]EnrollmentContextItem, 0, len(context.Children))
	for _, child := range context.Children {
		if !child.is(contextNS, "ContextItem") || !child.container() || len(child.Children) != 1 || len(child.Attrs) != 1 || child.Attrs[0].Name != (xml.Name{Local: "Name"}) {
			return nil, ErrWSTEP
		}
		value, err := child.one(contextNS, "Value")
		if err != nil {
			return nil, ErrWSTEP
		}
		text, err := value.plainText(8192)
		if err != nil {
			return nil, ErrWSTEP
		}
		items = append(items, EnrollmentContextItem{Name: child.Attrs[0].Value, Value: text})
	}
	if err := validateEnrollmentContext(items); err != nil {
		return nil, err
	}
	credential, err := parseUsernameCredential(message.Header)
	if err != nil {
		return nil, err
	}
	// Parsing limits the DER envelope; expensive public-key verification happens
	// only after invitation authorization in the issuing transaction.
	return &WSTEPRequest{MessageID: message.MessageID, Credential: credential, CSRDER: der, Context: items}, nil
}

func enrollmentContextValue(items []EnrollmentContextItem, name string) string {
	for _, item := range items {
		if item.Name == name {
			return item.Value
		}
	}
	return ""
}

func validateEnrollmentContext(items []EnrollmentContextItem) error {
	if len(items) == 0 || len(items) > maxEnrollmentContextItems {
		return ErrWSTEP
	}
	seen := map[string]int{}
	size := 0
	for _, item := range items {
		if len(item.Name) == 0 || len(item.Name) > 128 || len(item.Value) > 8192 || !utf8.ValidString(item.Value) || strings.TrimSpace(item.Value) != item.Value || strings.IndexFunc(item.Value, func(r rune) bool { return unicode.IsControl(r) || r == 0xfffe || r == 0xffff }) >= 0 {
			return ErrWSTEP
		}
		for _, r := range item.Name {
			if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
				return ErrWSTEP
			}
		}
		seen[item.Name]++
		if seen[item.Name] > 1 && item.Name != "MAC" && item.Name != "IMEI" {
			return ErrWSTEP
		}
		size += len(item.Name) + len(item.Value)
		if size > maxEnrollmentContextBytes {
			return ErrWSTEP
		}
		switch item.Name {
		case "OSEdition":
			if _, err := strconv.ParseUint(item.Value, 10, 32); err != nil {
				return ErrWSTEP
			}
		case "OSVersion", "ApplicationVersion":
			if !enrollmentVersionParts(item.Value) {
				return ErrWSTEP
			}
		case "EnrollmentType":
			if !slices.Contains([]string{"Full", "Device"}, item.Value) {
				return ErrWSTEP
			}
		case "DeviceType":
			if !slices.Contains([]string{"CIMClient_Windows", "WindowsPhone", "WindowsHandheld"}, item.Value) {
				return ErrWSTEP
			}
		case "DeviceID", "DeviceName":
			if item.Value == "" || len(item.Value) > 256 {
				return ErrWSTEP
			}
		case "TargetedUserLoggedIn", "UXInitiated", "NotInOobe":
			if !slices.Contains([]string{"true", "false", "True", "False", "1", "0"}, item.Value) {
				return ErrWSTEP
			}
		case "MAC", "IMEI":
			if item.Value == "" || len(item.Value) > 64 {
				return ErrWSTEP
			}
		}
	}
	for _, required := range []string{"OSEdition", "OSVersion", "ApplicationVersion", "DeviceName", "DeviceID", "DeviceType", "EnrollmentType"} {
		if seen[required] != 1 {
			return ErrWSTEP
		}
	}
	return nil
}

func enrollmentVersionParts(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

// The issuer discards all requested names, SANs and extensions. A valid CSR
// proves possession of this key only; it never grants a certificate identity.
func verifyEnrollmentCSR(der []byte, minimumBits int) (*x509.CertificateRequest, error) {
	if len(der) == 0 || len(der) > MaxEnrollmentCSRBytes || !slices.Contains([]int{2048, 3072, 4096}, minimumBits) {
		return nil, ErrCSR
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.Version != 0 {
		return nil, ErrCSR
	}
	key, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < minimumBits || key.N.BitLen() > 4096 || key.E != 65537 {
		return nil, ErrCSR
	}
	if csr.SignatureAlgorithm != x509.SHA256WithRSA && csr.SignatureAlgorithm != x509.SHA256WithRSAPSS {
		return nil, ErrCSR
	}
	if csr.CheckSignature() != nil {
		return nil, ErrCSR
	}
	return csr, nil
}
