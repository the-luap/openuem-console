package apple

import (
	"strings"
	"testing"

	"howett.net/plist"
)

func adCertificateSettings() map[string]any {
	return map[string]any{"CertServer": "CA.example.test.", "CertTemplate": "Machine"}
}

func adCertificatePayload(t *testing.T, settings map[string]any, scope string) map[string]any {
	t.Helper()
	p := map[string]any{}
	if err := buildADCertificatePayload(p, settings, scope); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestADCertificatePreservesExplicitValuesAndWireTypes(t *testing.T) {
	for _, scope := range []string{"System", "User"} {
		settings := adCertificateSettings()
		p := adCertificatePayload(t, settings, scope)
		if len(p) != 3 || p["CertServer"] != "CA.example.test." {
			t.Fatal("AD certificate added unselected defaults or changed server spelling")
		}
		settings["Description"] = "Certificate <identity>"
		settings["CertificateAuthority"] = "CN=Company CA,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=test"
		settings["CertificateAcquisitionMechanism"] = "RPC"
		settings["CertificateRenewalTimeInterval"] = 0
		settings["AllowAllAppsAccess"], settings["KeyIsExtractable"] = false, false
		settings["Keysize"] = 3072
		settings["EnableAutoRenewal"] = scope == "System"
		if scope == "User" {
			settings["PromptForCredentials"] = false
		}
		p = adCertificatePayload(t, settings, scope)
		data, err := plist.Marshal(p, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if _, err = plist.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded["CertificateRenewalTimeInterval"] != uint64(0) || decoded["Keysize"] != uint64(3072) || decoded["AllowAllAppsAccess"] != false || decoded["KeyIsExtractable"] != false || decoded["EnableAutoRenewal"] != (scope == "System") {
			t.Fatal("AD certificate lost explicit zero/false or plist integer types")
		}
		if err = validateADCertificatePayload(decoded, scope, &Device{Model: "Mac16,1", OSVersion: "10.13.4"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestADCertificateRejectsInvalidSettingsAndInteractiveMDMCredentials(t *testing.T) {
	for _, bad := range []struct {
		key   string
		value any
	}{
		{"CertServer", ""}, {"CertServer", "ca"}, {"CertServer", "https://ca.example.test"}, {"CertServer", "127.0.0.1"}, {"CertServer", "ca..example.test"}, {"CertServer", "ca-.example.test"}, {"CertServer", strings.Repeat("x", 64) + ".example.test"}, {"CertServer", "ca.example.test:443"}, {"CertServer", "* .example.test"},
		{"CertTemplate", ""}, {"CertTemplate", "synthetic-secret\nvalue"}, {"Description", true}, {"CertificateAuthority", false}, {"CertificateAcquisitionMechanism", "LDAP"},
		{"Keysize", 2048.0}, {"Keysize", -1}, {"Keysize", 1023}, {"Keysize", 8193}, {"Keysize", 2049}, {"CertificateRenewalTimeInterval", -1}, {"CertificateRenewalTimeInterval", 3651}, {"CertificateRenewalTimeInterval", "0"},
		{"AllowAllAppsAccess", "false"}, {"KeyIsExtractable", 0}, {"EnableAutoRenewal", "true"}, {"PromptForCredentials", true}, {"PromptForCredentials", false},
	} {
		settings := adCertificateSettings()
		settings[bad.key] = bad.value
		if err := buildADCertificatePayload(map[string]any{}, settings, "System"); err == nil || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("invalid AD certificate accepted or value echoed", bad.key, err)
		}
	}
	for _, key := range []string{"PromptForCredentials", "EnableAutoRenewal"} {
		settings := adCertificateSettings()
		settings[key] = true
		if err := buildADCertificatePayload(map[string]any{}, settings, "User"); err == nil {
			t.Fatal("unsupported user credential workflow accepted", key)
		}
	}
	if err := buildADCertificatePayload(map[string]any{}, adCertificateSettings(), "invalid"); err == nil {
		t.Fatal("invalid AD scope accepted")
	}
}

func TestADCertificateTargetAndPropertyVersionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		key               string
		value             any
		version, previous string
	}{
		{"", nil, "10.7", "10.6"},
		{"CertificateAuthority", "CN=Company CA", "10.8", "10.7"},
		{"CertificateAcquisitionMechanism", "HTTP", "10.8", "10.7"},
		{"PromptForCredentials", false, "10.8", "10.7"},
		{"AllowAllAppsAccess", false, "10.10", "10.9"},
		{"KeyIsExtractable", false, "10.10", "10.9"},
		{"Keysize", 2048, "10.11", "10.10"},
		{"EnableAutoRenewal", false, "10.13.4", "10.13.3"},
	} {
		settings := adCertificateSettings()
		if tc.key != "" {
			settings[tc.key] = tc.value
		}
		p := adCertificatePayload(t, settings, "User")
		if err := validateADCertificatePayload(p, "User", &Device{Model: "Mac16,1", OSVersion: tc.previous}); err == nil {
			t.Fatal("AD property accepted before introduction", tc.key)
		}
		if err := validateADCertificatePayload(p, "User", &Device{Model: "Mac16,1", OSVersion: tc.version}); err != nil {
			t.Fatal(tc.key, err)
		}
	}
	p := adCertificatePayload(t, adCertificateSettings(), "System")
	for _, d := range []*Device{{Model: "iPhone16,1", OSVersion: "18.0"}, {Model: "iPad16,1", OSVersion: "18.0"}, {Model: "Unknown", OSVersion: "15.0"}, {Model: "Mac16,1", OSVersion: "unknown"}} {
		if err := validateADCertificatePayload(p, "System", d); err == nil {
			t.Fatal("unsupported AD certificate target accepted")
		}
	}
}
