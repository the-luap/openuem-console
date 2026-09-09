package apple

import (
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func acmeProfileSettings() map[string]any {
	return map[string]any{"DirectoryURL": "https://ca.example.test/acme/directory", "ClientIdentifier": "synthetic-device-client", "KeyType": "ECSECPrimeRandom", "KeySize": 256, "HardwareBound": false, "SubjectLines": "O=Example\nCN=Client"}
}

func acmePayload(t *testing.T, settings map[string]any) map[string]any {
	t.Helper()
	p := map[string]any{}
	if err := buildACMECertificatePayload(p, settings, "System"); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestACMEPayloadWireTypesAndDefaults(t *testing.T) {
	settings := acmeProfileSettings()
	settings["Attest"] = false
	settings["UsageFlags"] = 0
	settings["KeyIsExtractable"] = false
	settings["AllowAllAppsAccess"] = false
	settings["ExtendedKeyUsageLines"] = "1.3.6.1.5.5.7.3.2\n1.3.6.1.5.5.7.3.4"
	settings["dNSName"] = "client.example.test"
	p := acmePayload(t, settings)
	data, err := plist.Marshal(p, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if _, err = plist.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if err = validateACMECertificatePayload(decoded, "User", &Device{Model: "Mac16,1", OSVersion: "13.1"}); err != nil {
		t.Fatal(err)
	}
	if decoded["KeySize"] != uint64(256) || decoded["UsageFlags"] != uint64(0) || decoded["Attest"] != false || decoded["HardwareBound"] != false || decoded["KeyIsExtractable"] != false || decoded["AllowAllAppsAccess"] != false {
		t.Fatal("ACME explicit zero/false or integer wire type changed")
	}
	if len(decoded["Subject"].([]any)) != 2 || len(decoded["ExtendedKeyUsage"].([]any)) != 2 || decoded["SubjectAltName"].(map[string]any)["dNSName"] != "client.example.test" {
		t.Fatal("ACME subject, alternative name or usages changed")
	}
	minimal := acmeProfileSettings()
	minimal["SubjectLines"] = ""
	p = acmePayload(t, minimal)
	if len(p["Subject"].([]any)) != 0 {
		t.Fatal("empty but required ACME subject changed")
	}
	for _, key := range []string{"Attest", "UsageFlags", "KeyIsExtractable", "AllowAllAppsAccess", "SubjectAltName", "ExtendedKeyUsage"} {
		if _, exists := p[key]; exists {
			t.Fatal("omitted ACME setting changed", key)
		}
	}
}

func TestACMEKeyAndInputBoundaries(t *testing.T) {
	for _, tc := range []struct {
		kind          string
		size          int
		hardware, bad bool
	}{
		{"RSA", 1024, false, false}, {"RSA", 1032, false, false}, {"RSA", 4096, false, false}, {"RSA", 1023, false, true}, {"RSA", 2049, false, true}, {"RSA", 4104, false, true}, {"RSA", 2048, true, true},
		{"ECSECPrimeRandom", 192, false, false}, {"ECSECPrimeRandom", 256, false, false}, {"ECSECPrimeRandom", 384, false, false}, {"ECSECPrimeRandom", 521, false, false},
		{"ECSECPrimeRandom", 256, true, false}, {"ECSECPrimeRandom", 384, true, false}, {"ECSECPrimeRandom", 192, true, true}, {"ECSECPrimeRandom", 521, true, true}, {"ECSECPrimeRandom", 512, false, true}, {"invalid", 256, false, true},
	} {
		settings := acmeProfileSettings()
		settings["KeyType"] = tc.kind
		settings["KeySize"] = tc.size
		settings["HardwareBound"] = tc.hardware
		if err := buildACMECertificatePayload(map[string]any{}, settings, "System"); (err != nil) != tc.bad {
			t.Fatal(tc, err)
		}
	}
	for _, tc := range []struct {
		key   string
		value any
	}{
		{"DirectoryURL", "http://ca.example.test/directory"}, {"DirectoryURL", "https://user:password@ca.example.test/directory"}, {"DirectoryURL", "https://ca.example.test/directory#fragment"}, {"DirectoryURL", "https://ca.example.test:99999/directory"},
		{"ClientIdentifier", ""}, {"ClientIdentifier", true}, {"ClientIdentifier", strings.Repeat("x", 8193)}, {"ClientIdentifier", "secret\x00value"},
		{"KeySize", 256.0}, {"KeySize", "256"}, {"HardwareBound", "false"}, {"Attest", true}, {"Attest", "false"}, {"KeyIsExtractable", 0}, {"AllowAllAppsAccess", 0},
		{"UsageFlags", 2}, {"UsageFlags", -1}, {"UsageFlags", 1.0}, {"Subject", nil}, {"Subject", []any{"CN=invalid"}}, {"SubjectAltName", map[string]any{"dNSName": []any{"one", "two"}}},
		{"ExtendedKeyUsage", []any{"CN"}}, {"ExtendedKeyUsage", []any{"1.40.1"}}, {"ExtendedKeyUsage", []any{"01.3.6"}}, {"ExtendedKeyUsage", []any{true}},
	} {
		p := acmePayload(t, acmeProfileSettings())
		p[tc.key] = tc.value
		if err := validateACMECertificatePayload(p, "System", nil); err == nil {
			t.Fatal("invalid ACME setting accepted", tc.key)
		}
	}
	for _, key := range []string{"DirectoryURL", "ClientIdentifier", "KeyType", "KeySize", "HardwareBound", "Subject"} {
		p := acmePayload(t, acmeProfileSettings())
		delete(p, key)
		if err := validateACMECertificatePayload(p, "System", nil); err == nil {
			t.Fatal("missing ACME requirement accepted", key)
		}
	}
	for _, tc := range []struct {
		key   string
		value any
	}{{"SubjectLines", true}, {"dNSName", []any{"one", "two"}}, {"ExtendedKeyUsageLines", []any{"1.2.3"}}, {"ExtendedKeyUsageLines", "CN"}} {
		settings := acmeProfileSettings()
		settings[tc.key] = tc.value
		if err := buildACMECertificatePayload(map[string]any{}, settings, "System"); err == nil {
			t.Fatal("invalid ACME editor input accepted", tc.key)
		}
	}
}

func TestACMEPlatformAndHardwareBoundaries(t *testing.T) {
	base := acmePayload(t, acmeProfileSettings())
	for _, tc := range []struct {
		model, version, scope string
		bad                   bool
	}{
		{"Mac16,1", "13.1", "System", false}, {"Mac16,1", "13.1", "User", false}, {"Mac16,1", "13.0", "System", true},
		{"iPhone16,1", "16.0", "System", false}, {"iPad16,1", "16.0", "System", false}, {"iPhone16,1", "15.7", "System", true}, {"iPhone16,1", "18.0", "User", true},
		{"unknown", "18.0", "System", true}, {"Mac16,1", "unknown", "System", true}, {"Mac16,1", "15.0", "invalid", true},
	} {
		if err := validateACMECertificatePayload(base, tc.scope, &Device{Model: tc.model, OSVersion: tc.version}); (err != nil) != tc.bad {
			t.Fatal(tc, err)
		}
	}
	for _, key := range []string{"KeyIsExtractable", "AllowAllAppsAccess"} {
		p := acmePayload(t, acmeProfileSettings())
		p[key] = false
		if err := validateACMECertificatePayload(p, "System", &Device{Model: "iPhone16,1", OSVersion: "18.0"}); err == nil {
			t.Fatal("Mac ACME option reached phone", key)
		}
	}
	now := time.Now()
	old := now.Add(-25 * time.Hour)
	yes, no := true, false
	p := acmePayload(t, acmeProfileSettings())
	p["HardwareBound"] = true
	p["Attest"] = true
	for _, tc := range []struct {
		model, version string
		silicon        *bool
		at             *time.Time
		bad            bool
	}{
		{"Mac16,1", "14.0", &yes, &now, false}, {"Mac16,1", "13.6", &yes, &now, true}, {"Mac16,1", "14.0", &yes, &old, true}, {"Mac16,1", "14.0", nil, &now, true},
		{"MacBookPro16,1", "14.0", &no, &now, false}, {"MacBookPro14,1", "14.0", &no, &now, true}, {"Macmini8,1", "14.0", &no, &now, false}, {"Macmini7,1", "14.0", &no, &now, true},
		{"iPhone16,1", "16.0", nil, nil, false},
	} {
		if err := validateACMECertificatePayload(p, "System", &Device{Model: tc.model, OSVersion: tc.version, AppleSilicon: tc.silicon, InventoryAt: tc.at}); (err != nil) != tc.bad {
			t.Fatal(tc.model, tc.version, err)
		}
	}
	for _, model := range []string{"MacBookPro15,1", "MacBookPro15,2", "MacBookPro15,3", "MacBookPro15,4", "MacBookPro16,1", "MacBookPro16,2", "MacBookPro16,3", "MacBookPro16,4", "MacBookAir8,1", "MacBookAir8,2", "MacBookAir9,1", "iMac20,1", "iMac20,2", "iMacPro1,1", "Macmini8,1", "MacPro7,1"} {
		if !macHasT2(model) {
			t.Fatal("documented T2 model missing", model)
		}
	}
	for _, model := range []string{"MacBookPro16,5", "MacBookAir9,2", "MacBookAir10,1", "Macmini9,1", "iMac20,3", "MacBook Pro", ""} {
		if macHasT2(model) {
			t.Fatal("unidentified model treated as T2", model)
		}
	}
}

func TestACMEClientNamespaceAndDeduplication(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"https://CA.Example.test:443", "https://ca.example.test/"},
		{"https://CA.Example.test.:0443/%64irectory/%7eclient%2fname", "https://ca.example.test/directory/~client%2Fname"},
		{"https://[2001:0db8:0000::1]:443/directory", "https://[2001:db8::1]/directory"},
		{"https://CA.Example.test:8443/Directory?tenant=One", "https://ca.example.test:8443/Directory?tenant=One"},
		{"https://[2001:db8::1]:443/directory", "https://[2001:db8::1]/directory"},
	} {
		got, err := acmeDirectory(tc.input)
		if err != nil || got != tc.want {
			t.Fatal(tc, got, err)
		}
	}
	p := acmePayload(t, acmeProfileSettings())
	same := acmePayload(t, acmeProfileSettings())
	same["DirectoryURL"] = "https://CA.EXAMPLE.TEST:443/acme/directory"
	other := acmePayload(t, acmeProfileSettings())
	other["ClientIdentifier"] = "different-client"
	data, err := plist.Marshal(map[string]any{"PayloadContent": []any{p, same, other, map[string]any{"PayloadType": "unrelated"}}}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	clients, err := acmeProfileClients(&Profile{Payload: data, Scope: "System"}, nil)
	if err != nil || len(clients) != 2 || clients[0].Identifier != "synthetic-device-client" || clients[1].Identifier != "different-client" {
		t.Fatal("ACME client namespace changed", err)
	}
}

func TestACMELegacyReferencesRetainIncompleteOldSettings(t *testing.T) {
	encode := func(items []any) []byte {
		t.Helper()
		data, err := plist.Marshal(map[string]any{"PayloadContent": items}, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	// Older uploads did not require the current ACME key schema. Their client
	// ownership must survive even when they cannot be newly assigned today.
	old := map[string]any{"PayloadType": "com.apple.security.acme", "DirectoryURL": "https://CA.example.test:443", "ClientIdentifier": "legacy-client"}
	clients, err := acmeLegacyClients(encode([]any{old, old, map[string]any{"PayloadType": "com.apple.wifi.managed"}}))
	if err != nil || len(clients) != 1 || clients[0].Directory != "https://ca.example.test/" || clients[0].Identifier != "legacy-client" {
		t.Fatal("old client reference erased or changed", err)
	}
	if clients, err = acmeLegacyClients(encode([]any{map[string]any{"PayloadType": "com.apple.wifi.managed"}})); err != nil || len(clients) != 0 {
		t.Fatal("non-ACME archive gained a client", err)
	}
	for _, data := range [][]byte{nil, []byte("invalid"), make([]byte, MaxProfileBytes+1), encode(nil), encode([]any{"not a dictionary"}), encode([]any{map[string]any{}}), encode([]any{map[string]any{"PayloadType": "com.apple.security.acme", "DirectoryURL": "https://ca.example.test"}})} {
		if _, err := acmeLegacyClients(data); err == nil {
			t.Fatal("unusable archive treated as evidence")
		}
	}
}
