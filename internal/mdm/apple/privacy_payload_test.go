package apple

import (
	"strings"
	"testing"
	"time"
)

func privacySettings(service, policy string) map[string]any {
	s := map[string]any{"Service": service, "Policy": policy, "Identifier": "com.example.App", "IdentifierType": "bundleID", "CodeRequirement": `identifier "com.example.App" and anchor apple generic`}
	if service == "AppleEvents" {
		s["AEReceiverIdentifier"] = "com.example.Receiver"
		s["AEReceiverIdentifierType"] = "bundleID"
		s["AEReceiverCodeRequirement"] = `identifier "com.example.Receiver" and anchor apple generic`
	}
	return s
}

func privacyTestPayload(t *testing.T, service, policy string) map[string]any {
	t.Helper()
	p := map[string]any{}
	if err := buildPrivacyPayload(p, privacySettings(service, policy), "System"); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPrivacyServicePoliciesAndVersionBoundaries(t *testing.T) {
	now := time.Now().Add(-time.Minute)
	for _, service := range PrivacyServices() {
		t.Run(service.Key, func(t *testing.T) {
			for _, policy := range []string{"allow", "deny", "user"} {
				p := map[string]any{}
				err := buildPrivacyPayload(p, privacySettings(service.Key, policy), "System")
				invalid := policy == "allow" && service.DenyOnly || policy == "user" && !service.StandardUser
				if (err != nil) != invalid {
					t.Fatal("privacy service policy boundary", policy, err)
				}
				if invalid {
					continue
				}
				minimum := service.Minimum
				if policy == "user" {
					minimum = "11.0"
				}
				d := &Device{Model: "Mac16,1", OSVersion: minimum, SecurityAt: &now, SecurityInventory: map[string]any{"ManagementStatus": map[string]any{"UserApprovedEnrollment": true}}}
				if err = validatePrivacyPayload(p, "System", d); err != nil {
					t.Fatal("supported privacy policy rejected", err)
				}
				identity := p["Services"].(map[string]any)[service.Key].([]any)[0].(map[string]any)
				if identity["StaticCode"] != nil || identity["Identifier"] != "com.example.App" {
					t.Fatal("default or case changed")
				}
				if policy == "user" {
					if identity["Authorization"] != "AllowStandardUserToSetSystemService" || identity["Allowed"] != nil {
						t.Fatal("user choice became a grant")
					}
				} else if identity["Allowed"] != (policy == "allow") || identity["Authorization"] != nil {
					t.Fatal("legacy boolean policy changed")
				}
				d.OSVersion = "10.13"
				if err = validatePrivacyPayload(p, "System", d); err == nil {
					t.Fatal("old version accepted")
				}
				if CompareVersions(minimum, "10.14") > 0 {
					d.OSVersion = "10.14"
					if err = validatePrivacyPayload(p, "System", d); err == nil {
						t.Fatal("service version ignored")
					}
				}
				d.OSVersion = "14.0"
				d.Model = "iPhone16,1"
				if err = validatePrivacyPayload(p, "System", d); err == nil {
					t.Fatal("phone accepted")
				}
				d.Model = "Mac16,1"
				if err = validatePrivacyPayload(p, "User", d); err == nil {
					t.Fatal("user channel accepted")
				}
			}
		})
	}
	for _, version := range []string{"26.2", "27.0"} {
		d := &Device{Model: "Mac16,1", OSVersion: version, SecurityAt: &now, SecurityInventory: map[string]any{"ManagementStatus": map[string]any{"UserApprovedEnrollment": true}}}
		if err := validatePrivacyPayload(privacyTestPayload(t, "Accessibility", "allow"), "System", d); (err != nil) != (version == "27.0") {
			t.Fatal("Accessibility grant removal boundary", version, err)
		}
		if err := validatePrivacyPayload(privacyTestPayload(t, "Accessibility", "deny"), "System", d); err != nil {
			t.Fatal("Accessibility denial incorrectly removed", err)
		}
	}
}

func TestPrivacyIdentityAndUploadedAuthorizationValidation(t *testing.T) {
	for _, change := range []map[string]any{
		{"Identifier": ""}, {"Identifier": "com.example.*"}, {"Identifier": true}, {"IdentifierType": "unknown"},
		{"IdentifierType": "path", "Identifier": "relative/binary"}, {"IdentifierType": "path", "Identifier": "/Applications/../bin/app"}, {"IdentifierType": "path", "Identifier": "/"},
		{"CodeRequirement": ""}, {"CodeRequirement": strings.Repeat("x", 8193)}, {"CodeRequirement": "requirement\x00hidden"}, {"CodeRequirement": true},
		{"StaticCode": "false"}, {"Comment": true}, {"Comment": strings.Repeat("x", 1025)},
		{"Allowed": nil}, {"Authorization": "Allow"}, {"AEReceiverIdentifier": "com.example.receiver"},
	} {
		p := privacyTestPayload(t, "SystemPolicyAllFiles", "allow")
		identity := p["Services"].(map[string]any)["SystemPolicyAllFiles"].([]any)[0].(map[string]any)
		for k, v := range change {
			identity[k] = v
		}
		if err := validatePrivacyPayload(p, "System", nil); err == nil {
			t.Fatal("invalid privacy identity accepted", change)
		}
	}
	for _, policy := range []any{"Allow", "Deny", "AllowStandardUserToSetSystemService", "invalid", true, nil} {
		p := privacyTestPayload(t, "ScreenCapture", "deny")
		identity := p["Services"].(map[string]any)["ScreenCapture"].([]any)[0].(map[string]any)
		delete(identity, "Allowed")
		identity["Authorization"] = policy
		valid := policy == "Deny" || policy == "AllowStandardUserToSetSystemService"
		if err := validatePrivacyPayload(p, "System", nil); (err == nil) != valid {
			t.Fatal("uploaded screen authorization boundary", policy, err)
		}
	}
	for _, key := range []string{"AEReceiverIdentifier", "AEReceiverIdentifierType", "AEReceiverCodeRequirement"} {
		p := privacyTestPayload(t, "AppleEvents", "allow")
		identity := p["Services"].(map[string]any)["AppleEvents"].([]any)[0].(map[string]any)
		delete(identity, key)
		if err := validatePrivacyPayload(p, "System", nil); err == nil {
			t.Fatal("missing Apple Events receiver accepted", key)
		}
	}
	p := privacyTestPayload(t, "AppleEvents", "allow")
	identity := p["Services"].(map[string]any)["AppleEvents"].([]any)[0].(map[string]any)
	identity["IdentifierType"], identity["Identifier"] = "path", "/Library/Application Support/Example/agent"
	identity["AEReceiverIdentifierType"], identity["AEReceiverIdentifier"] = "path", "/usr/local/bin/receiver"
	identity["StaticCode"] = false
	if err := validatePrivacyPayload(p, "System", nil); err != nil {
		t.Fatal("absolute binary identity rejected", err)
	}
	for _, services := range []any{nil, []any{}, map[string]any{"Unknown": []any{}}, map[string]any{"Camera": true}, map[string]any{"Camera": make([]any, 129)}} {
		if err := validatePrivacyPayload(map[string]any{"PayloadType": privacyPayloadType, "Services": services}, "System", nil); err == nil {
			t.Fatal("invalid service container accepted")
		}
	}
	p = privacyTestPayload(t, "Camera", "deny")
	delete(p["Services"].(map[string]any)["Camera"].([]any)[0].(map[string]any), "Allowed")
	if err := validatePrivacyPayload(p, "System", nil); err == nil {
		t.Fatal("missing permission accepted")
	}
}

func TestPrivacyRequiresFreshApprovalAndAuthorizationOS(t *testing.T) {
	now := time.Now().Add(-time.Minute)
	d := &Device{Model: "Mac16,1", OSVersion: "10.15", SecurityAt: &now, SecurityInventory: map[string]any{"ManagementStatus": map[string]any{"UserApprovedEnrollment": true}}}
	p := privacyTestPayload(t, "ScreenCapture", "user")
	if err := validatePrivacyPayload(p, "System", d); err == nil {
		t.Fatal("standard-user controls accepted before macOS 11")
	}
	d.OSVersion = "11.0"
	if err := validatePrivacyPayload(p, "System", d); err != nil {
		t.Fatal(err)
	}
	for _, delta := range []time.Duration{-25 * time.Hour, time.Hour} {
		stamp := time.Now().Add(delta)
		d.SecurityAt = &stamp
		if err := validatePrivacyPayload(p, "System", d); err == nil {
			t.Fatal("untrusted security timestamp accepted")
		}
	}
	d.SecurityAt = &now
	for _, management := range []map[string]any{{}, {"UserApprovedEnrollment": false}, {"UserApprovedEnrollment": true, "IsUserEnrollment": true}} {
		d.SecurityInventory["ManagementStatus"] = management
		if err := validatePrivacyPayload(p, "System", d); err == nil {
			t.Fatal("unsupported management approval accepted")
		}
	}
}
