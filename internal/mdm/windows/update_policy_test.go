package windows

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

func updateTestInt(v int) *int    { return &v }
func updateTestBool(v bool) *bool { return &v }
func updateTestPolicy() UpdatePolicy {
	return UpdatePolicy{QualityDeadlineDays: updateTestInt(7), QualityGraceDays: updateTestInt(2), QualityDeferralDays: updateTestInt(0), FeatureDeferralDays: updateTestInt(30), ActiveHoursStart: updateTestInt(8), ActiveHoursEnd: updateTestInt(17), NotificationLevel: updateTestInt(1)}
}

func TestUpdatePolicyValuesDependenciesAndSeparateVerification(t *testing.T) {
	policy := updateTestPolicy()
	configure, verify, err := UpdatePolicyCommands(policy, false)
	if err != nil || configure.Kind != "Atomic" || verify.Kind != "Sequence" || len(configure.Commands) != 7 || len(verify.Commands) != 14 {
		t.Fatal("typed policy did not compile into separate bounded steps", err)
	}
	if configure.Commands[0].Data.Text != "0" {
		t.Fatal("explicit zero was omitted")
	}
	for _, command := range configure.Commands {
		if command.Kind != "Replace" || command.Format != "int" {
			t.Fatal("unintended operation in typed configuration")
		}
	}
	for _, command := range verify.Commands {
		if command.Kind != "Get" || command.Data != nil {
			t.Fatal("verification contained mutation")
		}
	}
	remove, _, err := UpdatePolicyCommands(policy, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range remove.Commands {
		if command.Kind != "Delete" || command.Data != nil || command.Format != "" {
			t.Fatal("removal changed unmanaged settings")
		}
	}
	for _, bad := range []UpdatePolicy{
		{}, {QualityDeadlineDays: updateTestInt(-1)}, {QualityDeferralDays: updateTestInt(31)}, {FeatureDeferralDays: updateTestInt(366)},
		{QualityGraceDays: updateTestInt(1)}, {FeatureGraceDays: updateTestInt(2)}, {QualityNoAutoReboot: updateTestBool(false)},
		{ActiveHoursStart: updateTestInt(8)}, {ActiveHoursStart: updateTestInt(8), ActiveHoursEnd: updateTestInt(8)},
		{ActiveHoursStart: updateTestInt(1), ActiveHoursEnd: updateTestInt(23)}, {NotificationLevel: updateTestInt(3)},
	} {
		if bad.Validate() == nil {
			t.Fatal("invalid policy range or dependency accepted")
		}
	}
	if (UpdatePolicy{ActiveHoursStart: updateTestInt(22), ActiveHoursEnd: updateTestInt(6)}).Validate() != nil {
		t.Fatal("overnight active hours rejected")
	}
}

func updateTestPlatformState(version, edition, architecture, product string) *cspSessionCommand {
	state := &cspSessionCommand{}
	if number, ok := map[string]string{"Enterprise": "4", "Professional": "48", "ServerStandard": "7", "Core": "101"}[edition]; ok {
		edition = number
	}
	for uri, value := range map[string]string{updateVersionURI: version, updateEditionURI: edition, updateArchitectureURI: architecture, updateProductURI: product} {
		state.Operations = append(state.Operations, cspOperationResult{Kind: "Get", URI: uri, Status: 200, HasResult: true, Format: "chr", Text: value})
	}
	return state
}

func TestUpdatePlatformUsesCurrentEvidenceAndServicingFloors(t *testing.T) {
	for _, test := range []struct {
		version, edition, architecture, product string
		policy                                  UpdatePolicy
		compatible                              bool
	}{
		{"10.0.26100.1", "Enterprise", "9", "Windows 11 Enterprise", updateTestPolicy(), true},
		{"10.0.26100.1", "Professional", "12", "Windows 11 Pro", updateTestPolicy(), true},
		{"10.0.26100.1", "Enterprise", "0", "Windows 11 Enterprise", updateTestPolicy(), false},
		{"10.0.26100.1", "ServerStandard", "9", "Windows Server 2025", updateTestPolicy(), false},
		{"10.0.26100.1", "Core", "9", "Windows 11 Home", updateTestPolicy(), false},
		{"10.0.18362.1", "Professional", "0", "Windows 10 Pro", updateTestPolicy(), true},
		{"10.0.17763.1", "Enterprise", "9", "Windows 10 Enterprise", updateTestPolicy(), false},
		{"10.0.22621.1", "Enterprise", "9", "Windows 11 Enterprise", UpdatePolicy{QualityDeadlineDays: updateTestInt(7), QualityNoAutoReboot: updateTestBool(true)}, true},
		{"10.0.22000.1", "Enterprise", "9", "Windows 11 Enterprise", UpdatePolicy{QualityDeadlineDays: updateTestInt(7), QualityNoAutoReboot: updateTestBool(true)}, false},
	} {
		result := assessUpdatePlatform(test.policy, updateTestPlatformState(test.version, test.edition, test.architecture, test.product))
		if result.Compatible != test.compatible {
			t.Fatal("incorrect platform applicability", test.version, test.edition, result.Reason)
		}
	}
	for _, test := range []struct {
		version string
		want    bool
	}{
		{"10.0.17763.1851", false}, {"10.0.17763.1852", true}, {"10.0.18362.9999", false}, {"10.0.18363.1473", false}, {"10.0.18363.1474", true}, {"10.0.19041.905", false}, {"10.0.19041.906", true}, {"10.0.19042.906", true}, {"10.0.19043.1", true}, {"10.0.22000.1", true},
	} {
		version, ok := windowsVersion(test.version)
		if !ok || updateFeatureGraceAvailable(version) != test.want {
			t.Fatal("servicing revision floor collapsed across releases", test.version)
		}
	}
	for _, version := range []string{"10.0.26100", "010.0.26100.1", "10.0.26100.-1", "10.0.26100.1.2", "10.0.4294967296.1"} {
		if _, ok := windowsVersion(version); ok {
			t.Fatal("noncanonical device version accepted")
		}
	}
}

func TestUpdateReadbackDistinguishesConfigurationEffectiveValueAndRemoval(t *testing.T) {
	policy := UpdatePolicy{QualityDeadlineDays: updateTestInt(7)}
	for _, test := range []struct {
		configured, effective, status int
		remove                        bool
		want                          string
	}{
		{7, 7, 200, false, "verified"}, {7, 3, 200, false, "drifted"}, {3, 7, 200, false, "drifted"}, {0, 3, 404, false, "drifted"}, {0, 3, 404, true, "removed"}, {7, 7, 200, true, "drifted"}, {0, 0, 500, false, "verification_failed"},
	} {
		state := &cspSessionCommand{Operations: []cspOperationResult{
			{Kind: "Sequence", Status: 200},
			{Kind: "Get", URI: updateConfigRoot + "ConfigureDeadlineForQualityUpdates", Status: test.status, HasResult: test.status == 200, Format: "int", Text: strconv.Itoa(test.configured)},
			{Kind: "Get", URI: updateResultRoot + "ConfigureDeadlineForQualityUpdates", Status: 200, HasResult: true, Format: "int", Text: strconv.Itoa(test.effective)},
		}}
		results, phase, err := evaluateUpdateReadback(policy, test.remove, state)
		if err != nil || phase != test.want || len(results) != 1 {
			t.Fatal("incorrect typed read-back outcome", phase, err)
		}
	}
}

func TestUpdateReleaseSupportSeparatesEditionLifecycleAndESU(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		build               uint32
		edition, state, end string
		known               bool
	}{
		{19045, "Professional", "standard_support_ended", "2025-10-14", true},
		{19044, "EnterpriseS", "within_published_support", "2027-01-12", true},
		{19044, "IoTEnterpriseS", "within_published_support", "2032-01-13", true},
		{22631, "Professional", "standard_support_ended", "2025-11-11", true},
		{22631, "Enterprise", "within_published_support", "2026-11-10", true},
		{26100, "EnterpriseS", "within_published_support", "2029-10-09", true},
		{26100, "IoTEnterpriseS", "within_published_support", "2034-10-10", true},
		{28000, "IoTEnterprise", "unsupported_edition_release", "", false},
		{99999, "Enterprise", "unknown", "", false},
	} {
		p := UpdatePlatform{Edition: test.edition}
		known := updatePlatformRelease(&p, test.build, now)
		if known != test.known || p.SupportState != test.state || p.SupportEndsOn != test.end || p.ExtendedSecurityUpdates != "not_assessed" {
			t.Fatal("support lifecycle or entitlement was misclassified", test.build, test.edition)
		}
	}
	for _, test := range []struct {
		hour int
		want string
	}{{6, "within_published_support"}, {8, "standard_support_ended"}} {
		p := UpdatePlatform{Edition: "Professional"}
		updatePlatformRelease(&p, 26100, time.Date(2026, 10, 14, test.hour, 0, 0, 0, time.UTC))
		if p.SupportState != test.want {
			t.Fatal("support date ignored Microsoft's Pacific calendar")
		}
	}
	if code, name := updateEditionName("48"); code != 48 || name != "Professional" {
		t.Fatal("numeric Windows licensing edition mapping failed")
	}
	for _, value := range []string{"Professional", "048", "0x30", "-1", "4294967296"} {
		if _, name := updateEditionName(value); name != "" {
			t.Fatal("unverified edition representation accepted")
		}
	}
}

func FuzzUpdatePolicy(f *testing.F) {
	seed, _ := json.Marshal(updateTestFullPolicy())
	f.Add(seed)
	f.Add([]byte(`{"quality_deadline_days":0,"quality_no_auto_reboot":false}`))
	f.Add([]byte(`{"active_hours_start":22,"active_hours_end":6}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		var policy UpdatePolicy
		if decodeSyncMLProtectedJSON(data, &policy) != nil || policy.Validate() != nil {
			return
		}
		canonical, err := canonicalUpdatePolicy(policy)
		if err != nil {
			t.Fatal(err)
		}
		var restored UpdatePolicy
		if decodeSyncMLProtectedJSON(canonical, &restored) != nil {
			t.Fatal("valid typed intent could not be restored")
		}
		again, err := canonicalUpdatePolicy(restored)
		if err != nil || !bytes.Equal(again, canonical) {
			t.Fatal("canonical typed intent changed across restart")
		}
		for _, remove := range []bool{false, true} {
			configure, verify, err := UpdatePolicyCommands(restored, remove)
			if err != nil {
				t.Fatal("accepted policy could not compile", err)
			}
			specs := []CSPCommandSpec{configure, verify}
			for _, version := range []int{1, 2} {
				commands, err := updateRunCommands(&updateIntent{Version: version, Policy: restored}, remove)
				if err != nil || len(commands) < 3 || len(commands) > maxUpdateRunSteps {
					t.Fatal("accepted intent failed versioned compilation", err)
				}
				specs = append(specs, commands...)
				var reads []CSPCommandSpec
				for _, command := range commands[2:] {
					if version == 2 && (len(command.Commands) > 6 || len(command.Commands)%2 != 0) {
						t.Fatal("versioned batch exceeded its fixed read-pair bound")
					}
					reads = append(reads, command.Commands...)
				}
				reassembled, _, err := encodeCSPRequest(CSPCommandSpec{Kind: "Sequence", Commands: reads})
				original, _, originalErr := encodeCSPRequest(verify)
				if err != nil || originalErr != nil || !bytes.Equal(reassembled, original) {
					t.Fatal("versioned partition changed verification intent")
				}
			}
			for _, spec := range specs {
				payload, user, err := encodeCSPRequest(spec)
				if err != nil || user {
					t.Fatal("typed policy escaped its device command boundary", err)
				}
				if _, _, err := decodeCSPRequest(payload); err != nil {
					t.Fatal("typed command did not survive protected storage", err)
				}
			}
		}
	})
}
