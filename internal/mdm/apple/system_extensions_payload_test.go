package apple

import (
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func systemExtensionTestSettings(mode string) map[string]any {
	s := map[string]any{"ApprovalMode": mode}
	if mode != "block" {
		s["TeamIdentifier"] = "ABCDE12345"
		s["AllowUserOverrides"] = false
	}
	if mode == "listed" {
		s["BundleIdentifiers"] = "com.example.agent.extension\ncom.example.agent.extension\n"
	}
	return s
}

func TestSystemExtensionPayloadSchemaAndCompatibility(t *testing.T) {
	for _, mode := range []string{"listed", "team", "block"} {
		p := map[string]any{}
		if err := buildSystemExtensionsPayload(p, systemExtensionTestSettings(mode), "System"); err != nil {
			t.Fatal(mode, err)
		}
		if p["PayloadType"] != systemExtensionPayloadType || p["AllowUserOverrides"] != false {
			t.Fatal("policy changed", mode)
		}
		if mode == "listed" && len(p["AllowedSystemExtensions"].(map[string]any)["ABCDE12345"].([]any)) != 1 {
			t.Fatal("bundle lines were not deduplicated")
		}
		if mode == "block" && len(p) != 2 {
			t.Fatal("block policy invented an approval")
		}
	}
	for _, key := range []string{"AllowedTeamIdentifiers", "AllowedSystemExtensions", "AllowedSystemExtensionTypes", "RemovableSystemExtensions", "NonRemovableSystemExtensions", "NonRemovableFromUISystemExtensions"} {
		t.Run(key, func(t *testing.T) {
			p := map[string]any{"PayloadType": systemExtensionPayloadType, key: map[string]any{"ABCDE12345": []any{"com.example.agent.extension"}}}
			minimum := "10.15"
			if key == "AllowedTeamIdentifiers" {
				p[key] = []any{"ABCDE12345"}
			}
			if key == "AllowedSystemExtensionTypes" {
				p[key] = map[string]any{"ABCDE12345": []any{"DriverExtension", "NetworkExtension", "EndpointSecurityExtension"}}
			}
			if key == "RemovableSystemExtensions" {
				minimum = "12.0"
			}
			if strings.HasPrefix(key, "NonRemovable") {
				minimum = "15.0"
			}
			now := time.Now().Add(-time.Minute)
			d := &Device{Model: "Mac16,1", OSVersion: minimum, SecurityAt: &now, SecurityInventory: map[string]any{"ManagementStatus": map[string]any{"UserApprovedEnrollment": true, "IsUserEnrollment": false}}}
			if _, err := parseSystemExtensionPayload(p, "System", d); err != nil {
				t.Fatal("supported Mac rejected", err)
			}
			for _, version := range []string{"", "unknown", "10.14"} {
				d.OSVersion = version
				if _, err := parseSystemExtensionPayload(p, "System", d); err == nil {
					t.Fatal("unsupported version accepted", version)
				}
			}
			if minimum == "12.0" || minimum == "15.0" {
				d.OSVersion = "11.7"
				if minimum == "15.0" {
					d.OSVersion = "14.7"
				}
				if _, err := parseSystemExtensionPayload(p, "System", d); err == nil {
					t.Fatal("version gate bypassed")
				}
			}
			d.OSVersion = "15.0"
			if _, err := parseSystemExtensionPayload(p, "User", d); err == nil {
				t.Fatal("user channel accepted")
			}
			d.Model = "iPhone16,1"
			if _, err := parseSystemExtensionPayload(p, "System", d); err == nil {
				t.Fatal("phone accepted")
			}
			d.Model = "Mac16,1"
			for _, delta := range []time.Duration{-25 * time.Hour, time.Hour} {
				stamp := time.Now().Add(delta)
				d.SecurityAt = &stamp
				if _, err := parseSystemExtensionPayload(p, "System", d); err == nil {
					t.Fatal("untrusted security timestamp accepted")
				}
			}
			d.SecurityAt = &now
			d.SecurityInventory["ManagementStatus"] = map[string]any{"UserApprovedEnrollment": false}
			if _, err := parseSystemExtensionPayload(p, "System", d); err == nil {
				t.Fatal("unapproved MDM accepted")
			}
			d.SecurityInventory["ManagementStatus"] = map[string]any{"UserApprovedEnrollment": true, "IsUserEnrollment": true}
			if _, err := parseSystemExtensionPayload(p, "System", d); err == nil {
				t.Fatal("User Enrollment accepted")
			}
		})
	}
	invalid := []map[string]any{
		{"AllowUserOverrides": "false"}, {"AllowedTeamIdentifiers": "ABCDE12345"}, {"AllowedTeamIdentifiers": []any{"bad"}},
		{"AllowedSystemExtensions": map[string]any{"bad": []any{}}}, {"AllowedSystemExtensions": map[string]any{"ABCDE12345": "com.example.extension"}},
		{"AllowedSystemExtensions": map[string]any{"ABCDE12345": []any{true}}}, {"AllowedSystemExtensions": map[string]any{"ABCDE12345": []any{"com.example.*"}}},
		{"AllowedSystemExtensions": map[string]any{"ABCDE12345": make([]any, 129)}}, {"AllowedTeamIdentifiers": make([]any, 65)},
		{"AllowedSystemExtensionTypes": map[string]any{"ABCDE12345": []any{"KernelExtension"}}},
	}
	for _, p := range invalid {
		p["PayloadType"] = systemExtensionPayloadType
		if _, err := parseSystemExtensionPayload(p, "System", nil); err == nil {
			t.Fatal("malformed extension policy accepted")
		}
	}
	for _, change := range []map[string]any{{"ApprovalMode": "unknown"}, {"TeamIdentifier": "bad"}, {"AllowUserOverrides": "true"}, {"BundleIdentifiers": ""}, {"BundleIdentifiers": strings.Repeat("x", 16385)}, {"AllowedTypes": []any{"bad"}}, {"RemovableBundleIdentifiers": true}, {"PayloadScope": "User"}} {
		s := systemExtensionTestSettings("listed")
		scope := "System"
		for k, v := range change {
			s[k] = v
			if k == "PayloadScope" {
				scope = "User"
			}
		}
		if err := buildSystemExtensionsPayload(map[string]any{}, s, scope); err == nil {
			t.Fatal("invalid editor settings accepted", change)
		}
	}
	s := systemExtensionTestSettings("block")
	s["TeamIdentifier"] = "ABCDE12345"
	if err := buildSystemExtensionsPayload(map[string]any{}, s, "System"); err == nil {
		t.Fatal("inactive block fields accepted")
	}
}

func TestSystemExtensionCombinedPoliciesAndRemovalDistinctions(t *testing.T) {
	mapping := func() map[string]any { return map[string]any{"ABCDE12345": []any{"com.example.agent.extension"}} }
	for _, test := range []struct {
		name     string
		a, b     map[string]any
		conflict bool
	}{
		{"team versus bundle", map[string]any{"AllowedTeamIdentifiers": []any{"ABCDE12345"}}, map[string]any{"AllowedSystemExtensions": mapping()}, true},
		{"team versus empty bundle list", map[string]any{"AllowedTeamIdentifiers": []any{"ABCDE12345"}}, map[string]any{"AllowedSystemExtensions": map[string]any{"ABCDE12345": []any{}}}, true},
		{"overlapping bundle approvals", map[string]any{"AllowedSystemExtensions": mapping()}, map[string]any{"AllowedSystemExtensions": mapping()}, false},
		{"different teams", map[string]any{"AllowedTeamIdentifiers": []any{"OTHER12345"}}, map[string]any{"AllowedSystemExtensions": mapping()}, false},
		{"protected removal", map[string]any{"RemovableSystemExtensions": mapping()}, map[string]any{"NonRemovableSystemExtensions": mapping()}, true},
		{"UI protection permits app removal", map[string]any{"RemovableSystemExtensions": mapping()}, map[string]any{"NonRemovableFromUISystemExtensions": mapping()}, false},
		{"types combine", map[string]any{"AllowedSystemExtensionTypes": map[string]any{"ABCDE12345": []any{}}}, map[string]any{"AllowedSystemExtensionTypes": map[string]any{"ABCDE12345": []any{"DriverExtension"}}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.a["PayloadType"], test.b["PayloadType"] = systemExtensionPayloadType, systemExtensionPayloadType
			a, e := parseSystemExtensionPayload(test.a, "System", nil)
			if e != nil {
				t.Fatal(e)
			}
			b, e := parseSystemExtensionPayload(test.b, "System", nil)
			if e != nil {
				t.Fatal(e)
			}
			if a.conflicts(b) != test.conflict || b.conflicts(a) != test.conflict {
				t.Fatal("asymmetric or incorrect conflict")
			}
			data, e := plist.Marshal(map[string]any{"PayloadContent": []any{test.a, test.b}}, plist.XMLFormat)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = systemExtensionProfileRules(data, "System", nil); (e != nil) != test.conflict {
				t.Fatal("combined profile validation differs", e)
			}
			for key, value := range test.b {
				test.a[key] = value
			}
			if _, e = parseSystemExtensionPayload(test.a, "System", nil); (e != nil) != test.conflict {
				t.Fatal("single payload validation differs", e)
			}
		})
	}
}
