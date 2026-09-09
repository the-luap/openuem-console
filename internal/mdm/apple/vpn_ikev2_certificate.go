package apple

import (
	"errors"
	"slices"
	"strconv"

	"github.com/google/uuid"
)

func buildIKEv2CertificatePayload(payload, settings map[string]any, scope string) ([]any, error) {
	allowed := []string{"PayloadScope", "UserDefinedName", "RemoteAddress", "LocalIdentifier", "RemoteIdentifier", "AuthenticationMode", "CertificateType", "ServerCertificateIssuerCommonName", "ServerCertificateCommonName", "IdentityProfileData", "TrustProfileData"}
	for key := range settings {
		if !slices.Contains(allowed, key) {
			return nil, errors.New("unsupported IKEv2 certificate editor setting")
		}
	}
	mode := stringValue(settings, "AuthenticationMode")
	if mode != "machine" && mode != "eap-tls" {
		return nil, errors.New("select machine certificate or EAP-TLS authentication")
	}
	data, ok := settings["IdentityProfileData"].([]byte)
	if !ok {
		return nil, errors.New("select an identity certificate profile revision")
	}
	identities, err := certificateCompositionSource(data, scope, true)
	if err != nil {
		return nil, err
	}
	identity := identities[0]
	algorithm := stringValue(settings, "CertificateType")
	identityType := stringValue(identity, "PayloadType")
	if identityType != "com.apple.security.pkcs12" {
		expected := "RSA"
		if identityType == "com.apple.security.acme" && stringValue(identity, "KeyType") == "ECSECPrimeRandom" {
			size, _ := certificateInteger(identity["KeySize"])
			expected = "ECDSA" + strconv.FormatUint(size, 10)
		}
		if algorithm != expected && !(expected == "RSA" && algorithm == "RSA-PSS") {
			return nil, errors.New("the selected IKEv2 certificate algorithm does not match the source identity configuration")
		}
	}
	base := stringValue(payload, "PayloadIdentifier")
	identity["PayloadUUID"], identity["PayloadIdentifier"] = uuid.NewString(), base+".identity"
	additional := []any{identity}
	c := map[string]any{"AuthenticationMethod": "Certificate", "ExtendedAuthEnabled": 0, "PayloadCertificateUUID": identity["PayloadUUID"]}
	for _, key := range []string{"RemoteAddress", "LocalIdentifier", "RemoteIdentifier", "CertificateType", "ServerCertificateIssuerCommonName"} {
		c[key] = settings[key]
	}
	if value, exists := settings["ServerCertificateCommonName"]; exists && value != "" {
		c["ServerCertificateCommonName"] = value
	}
	if mode == "eap-tls" {
		c["ExtendedAuthEnabled"] = 1
		c["TLSMinimumVersion"], c["TLSMaximumVersion"] = "1.2", "1.2"
	}
	if value, exists := settings["TrustProfileData"]; exists {
		data, ok := value.([]byte)
		if !ok {
			return nil, errors.New("select a public certificate profile revision for VPN trust")
		}
		certificates, err := certificateCompositionSource(data, scope, false)
		if err != nil {
			return nil, err
		}
		for i, cert := range certificates {
			cert["PayloadUUID"], cert["PayloadIdentifier"] = uuid.NewString(), base+".trust."+strconv.Itoa(i+1)
			additional = append(additional, cert)
		}
	}
	payload["PayloadType"], payload["VPNType"], payload["UserDefinedName"], payload["IKEv2"] = "com.apple.vpn.managed", "IKEv2", settings["UserDefinedName"], c
	return additional, validateVPNPayload(payload, scope, nil)
}
