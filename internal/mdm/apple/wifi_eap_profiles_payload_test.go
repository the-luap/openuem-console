package apple

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"howett.net/plist"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func wifiCertificateSource(t *testing.T, scope, kind string) []byte {
	t.Helper()
	p := map[string]any{"PayloadUUID": uuid.NewString(), "PayloadIdentifier": "com.example.source.identity", "PayloadVersion": 1}
	var extra []any
	var err error
	switch kind {
	case "scep":
		err = buildSCEPCertificatePayload(p, map[string]any{"URL": "https://ca.example.test/scep", "Keysize": 2048, "Challenge": "synthetic-wifi-certificate-secret"}, scope)
	case "acme":
		settings := acmeProfileSettings()
		settings["ClientIdentifier"] = "synthetic-wifi-certificate-secret"
		err = buildACMECertificatePayload(p, settings, scope)
	case "pkcs12":
		data := pkcs12IdentityFixture(t, pkcs12.Modern2023, " synthetic-wifi-certificate-secret § ")
		err = buildPKCS12Payload(p, map[string]any{"IdentityData": data, "Password": " synthetic-wifi-certificate-secret § "}, scope)
	case "ad":
		p["PayloadType"] = "com.apple.ADCertificate.managed"
		p["CertServer"] = "ca.example.test"
		p["CertTemplate"] = "Machine"
	case "trust":
		now := time.Now()
		data := publicCertificateFixture(t, 701, true, now.Add(-time.Hour), now.Add(time.Hour))
		extra, err = buildPublicCertificatePayload(p, map[string]any{"CertificateData": data}, scope)
	default:
		t.Fatal("unknown fixture kind")
	}
	if err != nil {
		t.Fatal(err)
	}
	data, err := plist.Marshal(map[string]any{"PayloadType": "Configuration", "PayloadVersion": 1, "PayloadUUID": uuid.NewString(), "PayloadIdentifier": "com.example.source." + kind, "PayloadScope": scope, "PayloadContent": append([]any{p}, extra...)}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func wifiEAPSettings(t *testing.T, scope, kind string) map[string]any {
	t.Helper()
	return map[string]any{"SSID_STR": " Company café ", "EncryptionType": "WPA2", "TLSMinimumVersion": "1.2", "TLSMaximumVersion": "1.2", "ServerNameLines": "radius.example.test\nwpa.*.example.test", "AutoJoin": false, "HIDDEN_NETWORK": true, "IdentityProfileData": wifiCertificateSource(t, scope, kind)}
}

func wifiEAPPayload(t *testing.T, settings map[string]any, scope string) (map[string]any, []any) {
	t.Helper()
	p := map[string]any{"PayloadUUID": uuid.NewString(), "PayloadIdentifier": "com.example.enterprise.settings", "PayloadVersion": 1}
	extra, err := buildWiFiEAPTLSPayload(p, settings, scope)
	if err != nil {
		t.Fatal(err)
	}
	return p, extra
}

func TestWiFiEAPTLSCompositionKeepsCredentialsAndRebindsPayloads(t *testing.T) {
	for _, scope := range []string{"System", "User"} {
		for _, kind := range []string{"scep", "acme", "pkcs12", "ad"} {
			settings := wifiEAPSettings(t, scope, kind)
			settings["TrustProfileData"] = wifiCertificateSource(t, scope, "trust")
			original := bytes.Clone(settings["IdentityProfileData"].([]byte))
			var source map[string]any
			if _, err := plist.Unmarshal(original, &source); err != nil {
				t.Fatal(err)
			}
			p, extra := wifiEAPPayload(t, settings, scope)
			if len(extra) != 2 || p["SSID_STR"] != " Company café " || p["AutoJoin"] != false || p["HIDDEN_NETWORK"] != true || !bytes.Equal(original, settings["IdentityProfileData"].([]byte)) {
				t.Fatal("composition changed source, SSID or explicit booleans")
			}
			identity := extra[0].(map[string]any)
			originalIdentity := source["PayloadContent"].([]any)[0].(map[string]any)
			if identity["PayloadUUID"] == originalIdentity["PayloadUUID"] || identity["PayloadIdentifier"] == originalIdentity["PayloadIdentifier"] || p["PayloadCertificateUUID"] != identity["PayloadUUID"] {
				t.Fatal("copied certificate was not rebound to this profile")
			}
			switch kind {
			case "scep":
				if identity["PayloadContent"].(map[string]any)["Challenge"] != "synthetic-wifi-certificate-secret" {
					t.Fatal("SCEP challenge changed")
				}
			case "acme":
				if identity["ClientIdentifier"] != "synthetic-wifi-certificate-secret" {
					t.Fatal("ACME client changed")
				}
			case "pkcs12":
				if identity["Password"] != " synthetic-wifi-certificate-secret § " || !bytes.Equal(identity["PayloadContent"].([]byte), originalIdentity["PayloadContent"].([]byte)) {
					t.Fatal("PKCS12 identity changed")
				}
			}
			root := map[string]any{"PayloadScope": scope, "PayloadContent": append([]any{p}, extra...)}
			if err := validateProfileCertificateReferences(root); err != nil {
				t.Fatal(err)
			}
			data, err := plist.Marshal(root, plist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}
			if err = validateWiFiProfile(&Profile{Payload: data, Scope: scope}, &Device{Model: "Mac16,1", OSVersion: "15.0"}); err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if _, err = plist.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			wire := decoded["PayloadContent"].([]any)[0].(map[string]any)["EAPClientConfiguration"].(map[string]any)
			if wire["AcceptEAPTypes"].([]any)[0] != uint64(13) || wire["TLSCertificateIsRequired"] != true || len(wire["PayloadCertificateAnchorUUID"].([]any)) != 1 {
				t.Fatal("EAP wire types or trust changed")
			}
			for _, key := range []string{"UserPassword", "TLSAllowTrustExceptions", "UserName", "OuterIdentity"} {
				if _, exists := wire[key]; exists {
					t.Fatal("unselected credential or trust option emitted", key)
				}
			}
		}
	}
	settings := wifiEAPSettings(t, "System", "scep")
	p, _ := wifiEAPPayload(t, settings, "System")
	if _, exists := p["EAPClientConfiguration"].(map[string]any)["PayloadCertificateAnchorUUID"]; exists {
		t.Fatal("existing device trust gained explicit anchors")
	}
}

func TestWiFiEAPTLSCompositionRejectsInvalidInputs(t *testing.T) {
	base := wifiEAPSettings(t, "System", "scep")
	for _, bad := range []struct {
		key   string
		value any
	}{
		{"SSID_STR", ""}, {"SSID_STR", strings.Repeat("é", 17)}, {"SSID_STR", "line\nbreak"}, {"EncryptionType", "None"}, {"TLSMinimumVersion", "1.0"}, {"TLSMinimumVersion", "1.3"}, {"TLSMaximumVersion", 1.2},
		{"ServerNameLines", ""}, {"ServerNameLines", "*"}, {"ServerNameLines", "wpa*.example.test"}, {"ServerNameLines", strings.Repeat("radius.example.test\n", 65)}, {"UserName", true}, {"OuterIdentity", "bad\x00identity"}, {"AutoJoin", "false"}, {"HIDDEN_NETWORK", 0},
		{"IdentityProfileData", []byte("synthetic-wifi-certificate-secret")}, {"IdentityProfileData", wifiCertificateSource(t, "User", "scep")}, {"IdentityProfileData", wifiCertificateSource(t, "System", "trust")}, {"TrustProfileData", wifiCertificateSource(t, "User", "trust")}, {"TrustProfileData", wifiCertificateSource(t, "System", "scep")},
	} {
		settings := map[string]any{}
		for k, v := range base {
			settings[k] = v
		}
		settings[bad.key] = bad.value
		if _, err := buildWiFiEAPTLSPayload(map[string]any{}, settings, "System"); err == nil || strings.Contains(err.Error(), "synthetic-wifi-certificate-secret") {
			t.Fatal("invalid composition accepted or credential echoed", bad.key, err)
		}
	}
	settings := wifiEAPSettings(t, "System", "scep")
	settings["TLSMinimumVersion"] = "1.3"
	settings["TLSMaximumVersion"] = "1.3"
	if _, err := buildWiFiEAPTLSPayload(map[string]any{}, settings, "System"); err == nil {
		t.Fatal("TLS 1.3 minimum accepted without outer identity")
	}
	settings["OuterIdentity"] = "anonymous@example.test"
	settings["UserName"] = "Device-42"
	p, _ := wifiEAPPayload(t, settings, "System")
	if p["EAPClientConfiguration"].(map[string]any)["OuterIdentity"] != "anonymous@example.test" {
		t.Fatal("outer identity changed")
	}
	var root map[string]any
	if _, err := plist.Unmarshal(base["IdentityProfileData"].([]byte), &root); err != nil {
		t.Fatal(err)
	}
	root["PayloadContent"] = append(root["PayloadContent"].([]any), root["PayloadContent"].([]any)[0])
	data, err := plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = certificateCompositionSource(data, "System", true); err == nil {
		t.Fatal("multiple identity payloads silently selected")
	}
}

func TestWiFiEAPTargetAndTLSBoundaries(t *testing.T) {
	base, _ := wifiEAPPayload(t, wifiEAPSettings(t, "System", "scep"), "System")
	for _, tc := range []struct {
		model, version, scope, maximum string
		bad                            bool
	}{
		{"Mac16,1", "10.13", "System", "1.2", false}, {"Mac16,1", "10.12", "System", "1.2", true}, {"iPhone16,1", "11.0", "System", "1.2", false}, {"iPhone16,1", "10.3", "System", "1.2", true},
		{"Mac16,1", "14.0", "User", "1.3", false}, {"Mac16,1", "13.6", "System", "1.3", true}, {"iPhone16,1", "17.0", "System", "1.3", false}, {"iPad16,1", "16.0", "System", "1.3", true}, {"iPhone16,1", "18.0", "User", "1.2", true},
	} {
		base["EAPClientConfiguration"].(map[string]any)["TLSMaximumVersion"] = tc.maximum
		if err := validateWiFiEAPPayload(base, tc.scope, &Device{Model: tc.model, OSVersion: tc.version}); (err != nil) != tc.bad {
			t.Fatal(tc, err)
		}
	}
	for _, tc := range []struct {
		model, version string
		bad            bool
	}{{"iPhone16,1", "15.0", true}, {"iPhone16,1", "16.0", false}, {"Mac16,1", "12.6", true}, {"Mac16,1", "13.0", false}} {
		p := map[string]any{"PayloadType": "com.apple.wifi.managed", "EncryptionType": "WPA3"}
		if err := validateWiFiEAPPayload(p, "System", &Device{Model: tc.model, OSVersion: tc.version}); (err != nil) != tc.bad {
			t.Fatal(tc, err)
		}
	}
	for _, value := range []any{[]any{13.0}, []any{13, 13}, []any{999}, "13", []any{}} {
		base["EAPClientConfiguration"].(map[string]any)["AcceptEAPTypes"] = value
		if err := validateWiFiEAPPayload(base, "System", nil); err == nil {
			t.Fatal("invalid EAP types accepted", value)
		}
	}
}

func TestWiFiEAPUploadedSettingsRejectMalformedValuesAndRemovedKeys(t *testing.T) {
	for _, bad := range []struct {
		key   string
		value any
	}{
		{"TLSMinimumVersion", 1.2}, {"TLSMaximumVersion", "2.0"}, {"TLSMinimumVersion", "1.3"},
		{"TLSCertificateIsRequired", "true"}, {"TLSAllowTrustExceptions", 0},
		{"TLSTrustedServerNames", "radius.example.test"}, {"TLSTrustedServerNames", []any{}}, {"TLSTrustedServerNames", []any{"radius*.example.test"}},
		{"UserName", false}, {"OuterIdentity", "bad\nidentity"},
	} {
		p, _ := wifiEAPPayload(t, wifiEAPSettings(t, "System", "scep"), "System")
		p["EAPClientConfiguration"].(map[string]any)[bad.key] = bad.value
		if err := validateWiFiEAPPayload(p, "System", nil); err == nil {
			t.Fatal("invalid uploaded EAP setting accepted", bad.key)
		}
	}
	p := map[string]any{"PayloadType": "com.apple.wifi.managed", "EAPClientConfiguration": map[string]any{"AcceptEAPTypes": []any{13}, "TLSAllowTrustExceptions": false}}
	for _, tc := range []struct {
		model, version string
		bad            bool
	}{{"iPhone16,1", "7.0", false}, {"iPhone16,1", "8.0", true}, {"iPad16,1", "18.0", true}, {"Mac16,1", "15.0", false}} {
		if err := validateWiFiEAPPayload(p, "System", &Device{Model: tc.model, OSVersion: tc.version}); (err != nil) != tc.bad {
			t.Fatal("removed trust exception key boundary changed", tc, err)
		}
	}
	p["EAPClientConfiguration"] = "invalid"
	if err := validateWiFiEAPPayload(p, "System", nil); err == nil {
		t.Fatal("non-dictionary EAP accepted")
	}
}
