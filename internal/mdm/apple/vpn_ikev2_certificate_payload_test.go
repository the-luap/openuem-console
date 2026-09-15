package apple

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/uuid"
	"howett.net/plist"
)

func ikev2CertificateSettings(t *testing.T, scope, kind, mode string) map[string]any {
	t.Helper()
	algorithm := "RSA"
	if kind == "acme" {
		algorithm = "ECDSA256"
	}
	return map[string]any{"UserDefinedName": "Corporate VPN", "RemoteAddress": "vpn.example.test", "LocalIdentifier": "device.example.test", "RemoteIdentifier": "vpn.example.test", "AuthenticationMode": mode, "CertificateType": algorithm, "ServerCertificateIssuerCommonName": "Synthetic VPN issuer", "IdentityProfileData": wifiCertificateSource(t, scope, kind)}
}

func TestIKEv2CertificateBuilderCopiesCredentialsAndUsesLocalBindings(t *testing.T) {
	for _, scope := range []string{"System", "User"} {
		for _, kind := range []string{"scep", "acme", "pkcs12", "ad"} {
			for _, mode := range []string{"machine", "eap-tls"} {
				settings := ikev2CertificateSettings(t, scope, kind, mode)
				settings["TrustProfileData"] = wifiCertificateSource(t, scope, "trust")
				original := bytes.Clone(settings["IdentityProfileData"].([]byte))
				p := map[string]any{"PayloadIdentifier": "com.example.ikev2.settings", "PayloadVersion": 1, "PayloadUUID": uuid.NewString()}
				extra, err := buildIKEv2CertificatePayload(p, settings, scope)
				if err != nil {
					t.Fatal(scope, kind, mode, err)
				}
				if len(extra) != 2 || !bytes.Equal(original, settings["IdentityProfileData"].([]byte)) {
					t.Fatal("IKEv2 composition changed source or lost trust certificates")
				}
				var source map[string]any
				if _, err = plist.Unmarshal(original, &source); err != nil {
					t.Fatal(err)
				}
				identity := extra[0].(map[string]any)
				originalIdentity := source["PayloadContent"].([]any)[0].(map[string]any)
				if identity["PayloadUUID"] == originalIdentity["PayloadUUID"] || identity["PayloadIdentifier"] == originalIdentity["PayloadIdentifier"] {
					t.Fatal("IKEv2 identity was not rebound")
				}
				delete(originalIdentity, "PayloadUUID")
				delete(originalIdentity, "PayloadIdentifier")
				copied := map[string]any{}
				for key, value := range identity {
					if key != "PayloadUUID" && key != "PayloadIdentifier" {
						copied[key] = value
					}
				}
				want, e1 := plist.Marshal(originalIdentity, plist.XMLFormat)
				got, e2 := plist.Marshal(copied, plist.XMLFormat)
				if e1 != nil || e2 != nil || !bytes.Equal(want, got) {
					t.Fatal("IKEv2 composition changed identity credentials")
				}
				root := map[string]any{"PayloadContent": append([]any{p}, extra...)}
				if err = validateProfileCertificateReferences(root); err != nil {
					t.Fatal(err)
				}
				data, err := plist.Marshal(root, plist.XMLFormat)
				if err != nil {
					t.Fatal(err)
				}
				var decoded map[string]any
				if _, err = plist.Unmarshal(data, &decoded); err != nil {
					t.Fatal(err)
				}
				vpn := decoded["PayloadContent"].([]any)[0].(map[string]any)
				c := vpn["IKEv2"].(map[string]any)
				flag := uint64(0)
				if mode == "eap-tls" {
					flag = 1
				}
				if c["AuthenticationMethod"] != "Certificate" || c["ExtendedAuthEnabled"] != flag || c["PayloadCertificateUUID"] != identity["PayloadUUID"] {
					t.Fatal("IKEv2 authentication wire values changed")
				}
				for _, key := range []string{"TLSMinimumVersion", "TLSMaximumVersion"} {
					value, present := c[key]
					if present != (mode == "eap-tls") || present && value != "1.2" {
						t.Fatal("IKEv2 TLS bounds changed", mode, key)
					}
				}
				for _, key := range []string{"SharedSecret", "AuthPassword", "Password", "OnDemandEnabled", "IncludeAllNetworks", "PayloadCertificateAnchorUUID", "ServerCertificateCommonName"} {
					if _, exists := c[key]; exists {
						t.Fatal("unselected IKEv2 credential, routing or trust field emitted", key)
					}
				}
			}
		}
	}
}

func TestIKEv2CertificateBuilderRejectsInvalidOrCrossScopeSources(t *testing.T) {
	base := ikev2CertificateSettings(t, "System", "scep", "machine")
	for _, bad := range []struct {
		key   string
		value any
	}{
		{"AuthenticationMode", "password"}, {"UserDefinedName", ""}, {"RemoteAddress", "https://vpn.example.test"},
		{"LocalIdentifier", ""}, {"RemoteIdentifier", true}, {"CertificateType", "Unknown"}, {"ServerCertificateIssuerCommonName", ""},
		{"CertificateType", "ECDSA256"},
		{"ServerCertificateCommonName", true}, {"IdentityProfileData", []byte("synthetic-private-value")},
		{"IdentityProfileData", wifiCertificateSource(t, "User", "scep")}, {"IdentityProfileData", wifiCertificateSource(t, "System", "trust")},
		{"TrustProfileData", wifiCertificateSource(t, "User", "trust")}, {"TrustProfileData", wifiCertificateSource(t, "System", "scep")},
		{"SharedSecret", "synthetic-private-value"}, {"TLSMinimumVersion", "1.3"}, {"AlwaysOn", true},
	} {
		settings := map[string]any{}
		for key, value := range base {
			settings[key] = value
		}
		settings[bad.key] = bad.value
		if _, err := buildIKEv2CertificatePayload(map[string]any{}, settings, "System"); err == nil || strings.Contains(err.Error(), "synthetic-private-value") {
			t.Fatal("invalid IKEv2 certificate composition accepted or secret echoed", bad.key, err)
		}
	}
	p := map[string]any{"PayloadIdentifier": "com.example.ikev2"}
	base["ServerCertificateCommonName"] = "vpn-certificate.example.test"
	if extra, err := buildIKEv2CertificatePayload(p, base, "System"); err != nil || len(extra) != 1 || p["IKEv2"].(map[string]any)["ServerCertificateCommonName"] != "vpn-certificate.example.test" {
		t.Fatal("existing trust or server override lost", err)
	}
}
