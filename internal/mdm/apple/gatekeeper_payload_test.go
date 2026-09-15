package apple

import "testing"

func TestGatekeeperPayloadVersionAndTypeBoundaries(t *testing.T) {
	for _, kind := range []string{"com.apple.systempolicy.control", "com.apple.systempolicy.managed"} {
		keys := []string{"EnableAssessment", "AllowIdentifiedDevelopers", "EnableXProtectMalwareUpload"}
		if kind == "com.apple.systempolicy.managed" {
			keys = []string{"DisableOverride"}
		}
		for _, key := range keys {
			p := map[string]any{"PayloadType": kind, key: false}
			if err := validateGatekeeperPayload(p, "System", &Device{Model: "Mac16,1", OSVersion: "15.0"}); err != nil {
				t.Fatal("valid false switch rejected", err)
			}
			for _, value := range []any{"false", 0, nil, []any{false}, map[string]any{"value": false}} {
				p[key] = value
				if err := validateGatekeeperPayload(p, "System", nil); err == nil {
					t.Fatal("uploaded switch bypassed type validation", key)
				}
			}
		}
	}
	control := map[string]any{"PayloadType": "com.apple.systempolicy.control", "EnableAssessment": true}
	for _, tc := range []struct {
		model, version, scope string
		invalid               bool
	}{{"Mac16,1", "10.8", "System", false}, {"Mac16,1", "10.7", "System", true}, {"Mac16,1", "15.0", "User", true}, {"Mac16,1", "unknown", "System", true}, {"iPhone16,1", "18.0", "System", true}} {
		err := validateGatekeeperPayload(control, tc.scope, &Device{Model: tc.model, OSVersion: tc.version})
		if (err != nil) != tc.invalid {
			t.Fatal("Gatekeeper capability boundary", tc, err)
		}
	}
	control["EnableXProtectMalwareUpload"] = false
	if err := validateGatekeeperPayload(control, "System", &Device{Model: "Mac16,1", OSVersion: "14.7"}); err == nil {
		t.Fatal("macOS 15 key accepted on macOS 14")
	}
}
