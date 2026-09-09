package windows

import (
	"encoding/xml"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

const (
	EnrollmentNamespace     = "http://schemas.microsoft.com/windows/management/2012/01/enrollment"
	DiscoveryPath           = "/EnrollmentServer/Discovery.svc"
	DiscoveryAction         = EnrollmentNamespace + "/IDiscoveryService/Discover"
	DiscoveryResponseAction = DiscoveryAction + "Response"
	MaxDiscoveryBytes       = 128 << 10
)

var (
	ErrDiscovery        = errors.New("invalid Windows enrollment discovery request")
	ErrDiscoveryVersion = errors.New("unsupported Windows enrollment request version")
	ErrDiscoveryPolicy  = errors.New("Windows enrollment authentication policy is not offered")
)

// These values are unauthenticated routing and compatibility hints. They must
// never grant organization membership or establish a managed device identity.
type DiscoveryRequest struct {
	MessageID          string
	EmailAddress       string
	OSEdition          uint32
	RequestVersion     int
	DeviceType         string
	ApplicationVersion string
	AuthPolicies       []string
}

func ParseDiscovery(data []byte, expectedURL string) (*DiscoveryRequest, error) {
	message, err := parseSOAP(data, MaxDiscoveryBytes)
	if err != nil {
		return nil, err
	}
	if message.Action != DiscoveryAction {
		return nil, ErrDiscovery
	}
	if !sameEnrollmentEndpoint(message.To, expectedURL) {
		return nil, ErrEndpoint
	}
	// Microsoft's normative namespace has no trailing slash. Its published
	// MDE2 request examples use a slash; accept either consistently in the body.
	ns := message.Body.Name.Space
	if (ns != EnrollmentNamespace && ns != EnrollmentNamespace+"/") || message.Body.Name.Local != "Discover" || !discoveryContainer(message.Body) || len(message.Body.Children) != 1 {
		return nil, ErrDiscovery
	}
	request, err := message.Body.one(ns, "request")
	if err != nil || !discoveryContainer(request) || len(request.Children) != 6 {
		return nil, ErrDiscovery
	}
	fields := map[string]string{}
	for _, key := range []string{"EmailAddress", "OSEdition", "RequestVersion", "DeviceType", "ApplicationVersion"} {
		e, err := request.one(ns, key)
		if err != nil {
			return nil, ErrDiscovery
		}
		text, err := e.plainText(512)
		if err != nil || text == "" || strings.IndexFunc(text, unicode.IsControl) >= 0 {
			return nil, ErrDiscovery
		}
		fields[key] = text
	}
	if len(fields["EmailAddress"]) > 320 || !slices.Contains([]string{"WindowsPhone", "CIMClient_Windows"}, fields["DeviceType"]) {
		return nil, ErrDiscovery
	}
	edition, err := strconv.ParseUint(fields["OSEdition"], 10, 32)
	if err != nil {
		return nil, ErrDiscovery
	}
	version := discoveryVersion(fields["RequestVersion"])
	if version == 0 {
		return nil, ErrDiscoveryVersion
	}
	parts := strings.Split(fields["ApplicationVersion"], ".")
	if len(parts) != 4 {
		return nil, ErrDiscovery
	}
	for _, part := range parts {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return nil, ErrDiscovery
		}
	}
	policies, err := request.one(ns, "AuthPolicies")
	if err != nil || !discoveryContainer(policies) || len(policies.Children) < 1 || len(policies.Children) > 3 {
		return nil, ErrDiscoveryPolicy
	}
	result := &DiscoveryRequest{MessageID: message.MessageID, EmailAddress: fields["EmailAddress"], OSEdition: uint32(edition), RequestVersion: version, DeviceType: fields["DeviceType"], ApplicationVersion: fields["ApplicationVersion"]}
	for _, p := range policies.Children {
		if !p.is(ns, "AuthPolicy") {
			return nil, ErrDiscoveryPolicy
		}
		policy, err := p.plainText(32)
		if err != nil || !slices.Contains([]string{"OnPremise", "Federated", "Certificate"}, policy) || slices.Contains(result.AuthPolicies, policy) {
			return nil, ErrDiscoveryPolicy
		}
		result.AuthPolicies = append(result.AuthPolicies, policy)
	}
	return result, nil
}

func discoveryContainer(e *xmlElement) bool {
	if !e.container() {
		return false
	}
	for _, attr := range e.Attrs {
		if attr.Name != (xml.Name{Space: xsiNS, Local: "nil"}) || attr.Value != "false" && attr.Value != "0" {
			return false
		}
	}
	return true
}

func discoveryVersion(raw string) int {
	if len(raw) > 16 {
		return 0
	}
	parts := strings.Split(strings.TrimPrefix(raw, "+"), ".")
	if len(parts) > 2 || len(parts) == 2 && strings.Trim(parts[1], "0") != "" {
		return 0
	}
	n, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil || n < 1 || n > 9 {
		return 0
	}
	return int(n)
}

type DiscoveryOptions struct {
	AuthPolicy          string
	EnrollmentVersion   int
	EnrollmentPolicyURL string
	EnrollmentURL       string
	AuthenticationURL   string
}

type discoveryResponse struct {
	XMLName xml.Name        `xml:"http://schemas.microsoft.com/windows/management/2012/01/enrollment DiscoverResponse"`
	Result  discoveryResult `xml:"DiscoverResult"`
}
type discoveryResult struct {
	AuthPolicy          string `xml:"AuthPolicy"`
	EnrollmentVersion   string `xml:"EnrollmentVersion"`
	EnrollmentPolicyURL string `xml:"EnrollmentPolicyServiceUrl"`
	EnrollmentURL       string `xml:"EnrollmentServiceUrl"`
	AuthenticationURL   string `xml:"AuthenticationServiceUrl,omitempty"`
}

// Endpoint URLs come exclusively from operator configuration. Responding to
// discovery neither authenticates the supplied account nor issues a certificate.
func BuildDiscoveryResponse(request *DiscoveryRequest, options DiscoveryOptions) ([]byte, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	if request == nil || !validMessageID(request.MessageID) {
		return nil, ErrDiscovery
	}
	if request.RequestVersion < options.EnrollmentVersion || request.RequestVersion > 9 {
		return nil, ErrDiscoveryVersion
	}
	if !slices.Contains(request.AuthPolicies, options.AuthPolicy) {
		return nil, ErrDiscoveryPolicy
	}
	return soapResponse(DiscoveryResponseAction, request.MessageID, discoveryResponse{Result: discoveryResult{AuthPolicy: options.AuthPolicy, EnrollmentVersion: fmt.Sprintf("%d.0", options.EnrollmentVersion), EnrollmentPolicyURL: options.EnrollmentPolicyURL, EnrollmentURL: options.EnrollmentURL, AuthenticationURL: options.AuthenticationURL}})
}

func (options DiscoveryOptions) validate() error {
	if options.EnrollmentVersion < 3 || options.EnrollmentVersion > 9 {
		return ErrDiscoveryVersion
	}
	if !slices.Contains([]string{"OnPremise", "Federated", "Certificate"}, options.AuthPolicy) {
		return ErrDiscoveryPolicy
	}
	policy, err := enrollmentEndpoint(options.EnrollmentPolicyURL)
	if err != nil {
		return err
	}
	enrollment, err := enrollmentEndpoint(options.EnrollmentURL)
	if err != nil || !strings.EqualFold(policy.Hostname(), enrollment.Hostname()) {
		return ErrEndpoint
	}
	if options.AuthPolicy == "Federated" {
		if _, err := enrollmentEndpoint(options.AuthenticationURL); err != nil {
			return err
		}
	} else if options.AuthenticationURL != "" {
		return ErrDiscoveryPolicy
	}
	return nil
}
