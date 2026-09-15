package apple

import (
	"bytes"
	"strings"
	"testing"

	"howett.net/plist"
)

func scepProfileSettings() map[string]any {
	return map[string]any{"URL": "https://ca.example.test/scep", "Keysize": 2048}
}

func scepProfilePayload(t *testing.T, settings map[string]any) map[string]any {
	t.Helper()
	payload := map[string]any{}
	if err := buildSCEPCertificatePayload(payload, settings, "System"); err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestSCEPProfileTypedSettingsAndOptionalDefaults(t *testing.T) {
	settings := scepProfileSettings()
	settings["SubjectLines"] = "O=Example\r\nOU= Engineering \r\nCN=Client=42\n1.2.3.4=Literal\\value"
	settings["dNSName"] = "One.example.test\nTwo.example.test"
	settings["rfc822Name"] = "User@example.test"
	settings["ntPrincipalName"] = "First@example.test\nSecond@example.test"
	settings["Challenge"] = "synthetic-secret"
	settings["Key Usage"] = 5
	settings["Retries"] = 0
	settings["RetryDelay"] = 0
	settings["KeyIsExtractable"] = false
	settings["AllowAllAppsAccess"] = false
	settings["Fingerprint"] = strings.Repeat("AB:", 19) + "AB"
	payload := scepProfilePayload(t, settings)
	content := payload["PayloadContent"].(map[string]any)
	if payload["PayloadType"] != "com.apple.security.scep" || content["Key Type"] != "RSA" || content["Keysize"] != 2048 || content["Retries"] != 0 || content["RetryDelay"] != 0 || content["KeyIsExtractable"] != false || content["AllowAllAppsAccess"] != false {
		t.Fatal("SCEP types, zero or false values changed")
	}
	if !bytes.Equal(content["CAFingerprint"].([]byte), bytes.Repeat([]byte{0xAB}, 20)) {
		t.Fatal("SCEP fingerprint not decoded as data")
	}
	subject := content["Subject"].([]any)
	if len(subject) != 4 || subject[1].([]any)[0].([]any)[1] != " Engineering " || subject[2].([]any)[0].([]any)[1] != "Client=42" {
		t.Fatal("literal subject values changed")
	}
	names := content["SubjectAltName"].(map[string]any)
	if names["rfc822Name"] != "User@example.test" || len(names["dNSName"].([]any)) != 2 || len(names["ntPrincipalName"].([]any)) != 2 {
		t.Fatal("alternative-name scalar/array shape changed")
	}
	for _, d := range []*Device{{Model: "Mac16,1", OSVersion: "10.13.4"}, {Model: "iPhone16,1", OSVersion: "4.0"}} {
		if err := validateSCEPCertificatePayload(payload, "System", d); err != nil {
			t.Fatal("supported SCEP target rejected", err)
		}
	}
	wire, err := plist.Marshal(payload, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if _, err = plist.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	values := decoded["PayloadContent"].(map[string]any)
	if values["Keysize"] != uint64(2048) || values["Retries"] != uint64(0) {
		t.Fatal("wire integers lost their plist representation")
	}
	if err = validateSCEPCertificatePayload(decoded, "System", nil); err != nil {
		t.Fatal("serialized SCEP profile was rejected", err)
	}
	minimal := scepProfilePayload(t, scepProfileSettings())["PayloadContent"].(map[string]any)
	if len(minimal) != 3 {
		t.Fatal("SCEP editor invented optional defaults")
	}
	if err := validateSCEPCertificatePayload(map[string]any{"PayloadType": "com.apple.security.scep", "PayloadContent": map[string]any{"URL": "https://ca.example.test/scep"}}, "User", &Device{Model: "Mac16,1", OSVersion: "10.7"}); err != nil {
		t.Fatal("uploaded optional keys became required", err)
	}
}

func TestSCEPProfileVersionAndValidationBoundaries(t *testing.T) {
	for _, test := range []struct {
		key            string
		value          any
		minimum, older string
	}{{"Key Usage", 0, "10.11", "10.10"}, {"Retries", 0, "10.10", "10.9"}, {"RetryDelay", 0, "10.10", "10.9"}, {"AllowAllAppsAccess", false, "10.10", "10.9"}, {"KeyIsExtractable", false, "10.13.4", "10.13.3"}} {
		settings := scepProfileSettings()
		settings[test.key] = test.value
		payload := scepProfilePayload(t, settings)
		if err := validateSCEPCertificatePayload(payload, "System", &Device{Model: "Mac16,1", OSVersion: test.older}); err == nil {
			t.Fatal("Mac version gate bypassed", test.key)
		}
		if err := validateSCEPCertificatePayload(payload, "User", &Device{Model: "Mac16,1", OSVersion: test.minimum}); err != nil {
			t.Fatal("supported Mac option rejected", test.key, err)
		}
		if err := validateSCEPCertificatePayload(payload, "System", &Device{Model: "iPad16,1", OSVersion: "4.0"}); err != nil {
			t.Fatal("Mac minimum applied to iPad", test.key, err)
		}
	}
	for _, change := range []map[string]any{
		{"URL": "http://ca.example.test/scep"}, {"URL": "https://user:secret@ca.example.test/scep"}, {"URL": "ftp://ca.example.test/scep"}, {"URL": "https://ca.example.test:99999/scep"}, {"URL": "https://ca.example.test/scep#fragment"}, {"URL": false},
		{"Key Type": "EC"}, {"Keysize": 4095}, {"Keysize": 2048.0}, {"Key Usage": 2}, {"Key Usage": -1}, {"Key Usage": true}, {"KeyIsExtractable": "false"}, {"AllowAllAppsAccess": 0}, {"Retries": 101}, {"RetryDelay": 86401}, {"Retries": -1}, {"RetryDelay": 1.0},
		{"Challenge": true}, {"Challenge": strings.Repeat("x", 8193)}, {"Name": "invalid\x00name"}, {"CAFingerprint": "ABCD"}, {"CAFingerprint": make([]byte, 32)},
		{"Subject": []any{[]any{[]any{"invalid", "value"}}}}, {"Subject": []any{[]any{[]any{"CN"}}}}, {"Subject": []any{[]any{[]any{"CN", true}}}}, {"Subject": []any{[]any{}}},
		{"SubjectAltName": map[string]any{"unsupported": "value"}}, {"SubjectAltName": map[string]any{"dNSName": true}}, {"SubjectAltName": map[string]any{"dNSName": []any{true}}},
	} {
		payload := scepProfilePayload(t, scepProfileSettings())
		content := payload["PayloadContent"].(map[string]any)
		for k, v := range change {
			content[k] = v
		}
		if err := validateSCEPCertificatePayload(payload, "System", nil); err == nil {
			t.Fatal("invalid SCEP content accepted", change)
		}
	}
	for _, size := range []int{16, 20} {
		payload := scepProfilePayload(t, scepProfileSettings())
		content := payload["PayloadContent"].(map[string]any)
		content["URL"] = "http://ca.example.test/scep"
		content["CAFingerprint"] = make([]byte, size)
		if err := validateSCEPCertificatePayload(payload, "System", nil); err != nil {
			t.Fatal("pinned HTTP SCEP rejected", err)
		}
	}
	payload := scepProfilePayload(t, scepProfileSettings())
	for _, test := range []struct{ model, version, scope string }{{"Mac16,1", "10.6", "System"}, {"unknown", "15.0", "System"}, {"iPhone16,1", "3.0", "System"}, {"iPhone16,1", "18.0", "User"}, {"Mac16,1", "unknown", "System"}, {"Mac16,1", "15.0", "invalid"}} {
		if err := validateSCEPCertificatePayload(payload, test.scope, &Device{Model: test.model, OSVersion: test.version}); err == nil {
			t.Fatal("unsupported SCEP target", test)
		}
	}
}

func TestCertificateSubjectAndNameBounds(t *testing.T) {
	for _, oid := range []string{"CN", "1.2.840.113549.1.9.1", "2.5.4.3"} {
		if !certificateOID(oid, true) {
			t.Fatal("valid subject OID rejected", oid)
		}
	}
	for _, oid := range []string{"cn", "DC", "3.1", "1.40", "1.02", "1.-2", "1", "1.2.999999999999999999999"} {
		if certificateOID(oid, true) {
			t.Fatal("invalid subject OID accepted", oid)
		}
	}
	for _, raw := range []string{"CN", "CN=", "CN=value\x00", strings.Repeat("CN=value\n", 65), strings.Repeat("x", 16385)} {
		if _, err := certificateSubjectLines(raw); err == nil {
			t.Fatal("invalid subject lines accepted")
		}
	}
	if _, err := certificateNameLines(strings.Repeat("name\n", 65)); err == nil {
		t.Fatal("unbounded alternative name list accepted")
	}
	if _, err := certificateNameLines(strings.Repeat("x", 16385)); err == nil {
		t.Fatal("oversized name list accepted")
	}
	if err := validateCertificateSubject([]any{[]any{[]any{"CN", "One"}, []any{"OU", "Two"}}}); err != nil {
		t.Fatal("multi-valued RDN rejected", err)
	}
	for _, value := range []any{-1, 1.0, true, "1"} {
		if _, ok := certificateInteger(value); ok {
			t.Fatal("noninteger certificate option accepted")
		}
	}
}
