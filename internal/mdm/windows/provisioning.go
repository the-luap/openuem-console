package windows

import (
	"crypto/rand"
	"crypto/sha1" // Windows certificate-store thumbprints, never trust verification.
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxProvisioningBytes = 64 << 10

var ErrProvisioning = errors.New("invalid native Windows provisioning configuration")

type EnrollmentOptions struct {
	ManagementURL string
	ProviderID    string
	DisplayName   string
}

func (o EnrollmentOptions) validate() error {
	if _, err := enrollmentEndpoint(o.ManagementURL); err != nil {
		return ErrProvisioning
	}
	if len(o.ProviderID) == 0 || len(o.ProviderID) > 64 {
		return ErrProvisioning
	}
	for _, r := range o.ProviderID {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return ErrProvisioning
		}
	}
	if len(o.DisplayName) == 0 || len(o.DisplayName) > 128 || !utf8.ValidString(o.DisplayName) || strings.TrimSpace(o.DisplayName) != o.DisplayName || strings.IndexFunc(o.DisplayName, func(r rune) bool { return unicode.IsControl(r) || r == 0xfffe || r == 0xffff }) >= 0 {
		return ErrProvisioning
	}
	return nil
}

// CLIENT authenticates the server to the device; APPSRV authenticates the device
// to the server. Both secrets and their independent initial nonces are random.
// This structure must stay private and be encrypted before it leaves memory.
type syncMLBootstrapSecrets struct {
	ClientSecret string
	ServerSecret string
	ClientNonce  string
	ServerNonce  string
}

func (syncMLBootstrapSecrets) String() string   { return "[protected Windows SyncML credentials]" }
func (syncMLBootstrapSecrets) GoString() string { return "[protected Windows SyncML credentials]" }

func (s syncMLBootstrapSecrets) validate() error {
	for _, value := range []string{s.ClientSecret, s.ServerSecret, s.ClientNonce, s.ServerNonce} {
		decoded, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value {
			return ErrProvisioning
		}
		clear(decoded)
	}
	return nil
}

func newSyncMLBootstrapSecrets() (*syncMLBootstrapSecrets, error) {
	values := make([]string, 4)
	for i := range values {
		value := make([]byte, 32)
		if _, err := rand.Read(value); err != nil {
			return nil, ErrProvisioning
		}
		values[i] = base64.StdEncoding.EncodeToString(value)
		clear(value)
	}
	return &syncMLBootstrapSecrets{ClientSecret: values[0], ServerSecret: values[1], ClientNonce: values[2], ServerNonce: values[3]}, nil
}

type provisioningDocument struct {
	XMLName         xml.Name                     `xml:"wap-provisioningdoc"`
	Version         string                       `xml:"version,attr"`
	Characteristics []provisioningCharacteristic `xml:"characteristic"`
}
type provisioningCharacteristic struct {
	Type       string                       `xml:"type,attr"`
	Parameters []provisioningParameter      `xml:"parm"`
	Children   []provisioningCharacteristic `xml:"characteristic"`
}
type provisioningParameter struct {
	Name     string  `xml:"name,attr"`
	Value    *string `xml:"value,attr,omitempty"`
	DataType string  `xml:"datatype,attr,omitempty"`
}

func provisioningParam(name, value, datatype string) provisioningParameter {
	return provisioningParameter{Name: name, Value: &value, DataType: datatype}
}

func provisioningCertificate(cert *x509.Certificate) provisioningCharacteristic {
	thumbprint := sha1.Sum(cert.Raw)
	return provisioningCharacteristic{Type: strings.ToUpper(hex.EncodeToString(thumbprint[:])), Parameters: []provisioningParameter{provisioningParam("EncodedCertificate", base64.StdEncoding.EncodeToString(cert.Raw), "")}}
}

func buildProvisioningDocument(options EnrollmentOptions, deviceID, enrollmentType string, root, certificate *x509.Certificate, secrets *syncMLBootstrapSecrets) ([]byte, error) {
	if options.validate() != nil || !canonicalInvitationID(deviceID) || (enrollmentType != "Full" && enrollmentType != "Device") || root == nil || certificate == nil || secrets == nil {
		return nil, ErrProvisioning
	}
	if certificate.Subject.CommonName != "OpenUEM Windows "+deviceID || certificate.IsCA || certificate.CheckSignatureFrom(root) != nil {
		return nil, ErrProvisioning
	}
	if err := secrets.validate(); err != nil {
		return nil, err
	}
	location := "User"
	if enrollmentType == "Device" {
		location = "System"
	}
	rootStore := provisioningCharacteristic{Type: "CertificateStore", Children: []provisioningCharacteristic{{Type: "Root", Children: []provisioningCharacteristic{{Type: "System", Children: []provisioningCharacteristic{provisioningCertificate(root)}}}}}}
	personalStore := provisioningCharacteristic{Type: "CertificateStore", Children: []provisioningCharacteristic{{Type: "My", Children: []provisioningCharacteristic{{Type: location, Children: []provisioningCharacteristic{provisioningCertificate(certificate), {Type: "PrivateKeyContainer"}}}}}}}
	// MS-MDE2 specifies the logical My\User search store in both context examples.
	// Certificate installation itself follows the enrollment context above.
	criteria := "Subject=" + url.QueryEscape("CN="+certificate.Subject.CommonName) + "&Stores=My%5CUser"
	criteria = strings.ReplaceAll(criteria, "+", "%20")
	application := provisioningCharacteristic{Type: "APPLICATION", Parameters: []provisioningParameter{
		provisioningParam("APPID", "w7", ""), provisioningParam("PROVIDER-ID", options.ProviderID, ""), provisioningParam("NAME", options.DisplayName, ""),
		provisioningParam("ADDR", options.ManagementURL, ""), provisioningParam("PROTOVER", "1.2", ""), provisioningParam("ROLE", "32", ""),
		provisioningParam("DEFAULTENCODING", "application/vnd.syncml.dm+xml", ""), provisioningParam("CONNRETRYFREQ", "3", ""),
		provisioningParam("INITIALBACKOFFTIME", "30000", ""), provisioningParam("MAXBACKOFFTIME", "120000", ""),
		{Name: "BACKCOMPATRETRYDISABLED"}, provisioningParam("SSLCLIENTCERTSEARCHCRITERIA", criteria, ""),
	}, Children: []provisioningCharacteristic{
		{Type: "APPAUTH", Parameters: []provisioningParameter{provisioningParam("AAUTHLEVEL", "CLIENT", ""), provisioningParam("AAUTHTYPE", "DIGEST", ""), provisioningParam("AAUTHNAME", options.ProviderID, ""), provisioningParam("AAUTHSECRET", secrets.ServerSecret, ""), provisioningParam("AAUTHDATA", secrets.ServerNonce, "")}},
		{Type: "APPAUTH", Parameters: []provisioningParameter{provisioningParam("AAUTHLEVEL", "APPSRV", ""), provisioningParam("AAUTHTYPE", "DIGEST", ""), provisioningParam("AAUTHNAME", deviceID, ""), provisioningParam("AAUTHSECRET", secrets.ClientSecret, ""), provisioningParam("AAUTHDATA", secrets.ClientNonce, "")}},
	}}
	poll := provisioningCharacteristic{Type: "Poll", Parameters: []provisioningParameter{
		provisioningParam("NumberOfFirstRetries", "8", "integer"), provisioningParam("IntervalForFirstSetOfRetries", "15", "integer"),
		provisioningParam("NumberOfSecondRetries", "5", "integer"), provisioningParam("IntervalForSecondSetOfRetries", "60", "integer"),
		provisioningParam("NumberOfRemainingScheduledRetries", "0", "integer"), provisioningParam("IntervalForRemainingScheduledRetries", "1560", "integer"),
		provisioningParam("PollOnLogin", "true", "boolean"),
	}}
	client := provisioningCharacteristic{Type: "DMClient", Children: []provisioningCharacteristic{{Type: "Provider", Children: []provisioningCharacteristic{{Type: options.ProviderID, Parameters: []provisioningParameter{provisioningParam("EntDMID", deviceID, "string")}, Children: []provisioningCharacteristic{poll}}}}}}
	// Renewal is deliberately not advertised until the certificate-authenticated
	// renewal protocol exists. No Registry fallback, push or attestation is added.
	data, err := xml.Marshal(provisioningDocument{Version: "1.1", Characteristics: []provisioningCharacteristic{rootStore, personalStore, application, client}})
	if err != nil || len(data) > maxProvisioningBytes {
		return nil, ErrProvisioning
	}
	return data, nil
}

type wstepResponseCollection struct {
	XMLName  xml.Name      `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 RequestSecurityTokenResponseCollection"`
	Response wstepResponse `xml:"RequestSecurityTokenResponse"`
}
type wstepResponse struct {
	TokenType   string              `xml:"TokenType"`
	Disposition string              `xml:"http://schemas.microsoft.com/windows/pki/2009/01/enrollment DispositionMessage"`
	Token       wstepRequestedToken `xml:"RequestedSecurityToken"`
	RequestID   string              `xml:"http://schemas.microsoft.com/windows/pki/2009/01/enrollment RequestID"`
}
type wstepRequestedToken struct {
	Token provisioningToken `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd BinarySecurityToken"`
}
type provisioningToken struct {
	ValueType    string `xml:"ValueType,attr"`
	EncodingType string `xml:"EncodingType,attr"`
	Value        string `xml:",chardata"`
}

func buildWSTEPResponse(messageID string, requestID int64, provisioning []byte) ([]byte, error) {
	if !validMessageID(messageID) || requestID <= 0 || len(provisioning) == 0 || len(provisioning) > maxProvisioningBytes {
		return nil, ErrWSTEP
	}
	return soapResponse(WSTEPResponseAction, messageID, wstepResponseCollection{Response: wstepResponse{TokenType: deviceTokenType, RequestID: strconv.FormatInt(requestID, 10), Token: wstepRequestedToken{Token: provisioningToken{ValueType: provisionTokenType, EncodingType: binaryEncodingType, Value: base64.StdEncoding.EncodeToString(provisioning)}}}})
}

func enrollmentSecretPurpose(kind string, tenant, site int, deviceID, authorityID string, fingerprint, requestDigest, configDigest []byte) string {
	return fmt.Sprintf("openuem/windows/%s/v1/%d/%d/%s/%s/%x/%x/%x", kind, tenant, site, deviceID, authorityID, fingerprint, requestDigest, configDigest)
}
