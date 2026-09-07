package apple

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"howett.net/plist"
)

func TestProfileValidationAndRevisionIdentity(t *testing.T) {
	b, err := BuildProfile("Company Wi-Fi", "eu.example.wifi", "wifi", map[string]any{"SSID_STR": "Office", "EncryptionType": "WPA2", "Password": "correct-password"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := ParseProfile(b)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseProfile(b)
	if err != nil {
		t.Fatal(err)
	}
	if a.Identifier != c.Identifier || a.UUID == c.UUID {
		t.Fatal("revisions must keep identifier and change verification UUID")
	}
	var root map[string]any
	if _, err = plist.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	root["PayloadContent"].([]any)[0].(map[string]any)["PayloadType"] = "com.apple.mdm"
	b, err = plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseProfile(b); err == nil {
		t.Fatal("MDM enrollment payload accepted as a configuration")
	}
	if _, err = ParseProfile(bytes.Repeat([]byte("a"), MaxProfileBytes+1)); err == nil {
		t.Fatal("oversize profile accepted")
	}
}

func TestSecretBoxBindsTenantResourceAndPurpose(t *testing.T) {
	box, err := newSecretBox("01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	purpose := secretPurpose(1, "device-a", "push_token")
	ciphertext, err := box.seal([]byte("private"), purpose)
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []string{secretPurpose(2, "device-a", "push_token"), secretPurpose(1, "device-b", "push_token"), secretPurpose(1, "device-a", "profile")} {
		if _, err = box.open(ciphertext, other); err == nil {
			t.Fatal("ciphertext accepted under a different context")
		}
	}
	plain, err := box.open(ciphertext, purpose)
	if err != nil || string(plain) != "private" {
		t.Fatal("round-trip failed", err)
	}
	ciphertext[len(ciphertext)-1] ^= 1
	if _, err = box.open(ciphertext, purpose); err == nil {
		t.Fatal("tampering was accepted")
	}
}

func TestDDMStableTokensRemovalAndDeadline(t *testing.T) {
	d := Device{ID: uuid.NewString(), OSVersion: "18.6", Status: "enrolled"}
	p := UpdatePolicy{TargetVersion: "18.7.1", Deadline: "2026-10-01T18:00:00"}
	if err := ValidateUpdatePolicy(d, p); err != nil {
		t.Fatal(err)
	}
	first := Declarations(d, &p)
	second := Declarations(d, &p)
	if Manifest(first).DeclarationsToken != Manifest(second).DeclarationsToken {
		t.Fatal("unchanged declarations changed token")
	}
	p.Deadline = "2026-10-02T18:00:00"
	if Manifest(first).DeclarationsToken == Manifest(Declarations(d, &p)).DeclarationsToken {
		t.Fatal("changed deadline did not change token")
	}
	if Manifest(first).DeclarationsToken == Manifest(Declarations(d, nil)).DeclarationsToken {
		t.Fatal("policy removal did not change token")
	}
	if _, err := DeclarationResponse(Declarations(d, nil), "declaration/configuration/eu.openuem.apple."+d.ID+".update"); err != ErrNotFound {
		t.Fatal("removed declaration is still available")
	}
	p.Deadline = "2026-10-01T18:00:00Z"
	if err := ValidateUpdatePolicy(d, p); err == nil {
		t.Fatal("UTC deadline was accepted as device-local time")
	}
	b, _ := json.Marshal(Tokens(first))
	if !bytes.Contains(b, []byte("SyncTokens")) {
		t.Fatal("incorrect token envelope")
	}
}

func TestUpdateComplianceUsesFreshEvidenceAndNumericVersions(t *testing.T) {
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	fresh := now.Add(-time.Minute)
	d := Device{Status: "enrolled", OSVersion: "18.10.1", InventoryAt: &old}
	p := UpdatePolicy{TargetVersion: "18.9"}
	if UpdateCompliance(d, p, now) != "unknown" {
		t.Fatal("stale inventory marked compliant")
	}
	d.InventoryAt = &fresh
	if UpdateCompliance(d, p, now) != "compliant" {
		t.Fatal("versions were not compared numerically")
	}
	d.OSVersion = "18.9"
	p.TargetBuild = "22A001"
	d.BuildVersion = "22A000"
	if UpdateCompliance(d, p, now) != "update_required" {
		t.Fatal("wrong target build marked compliant")
	}
	d.Status = "unenrolled"
	if UpdateCompliance(d, p, now) != "not_managed" {
		t.Fatal("unenrolled device marked compliant")
	}
}

func TestDDMIncrementalStatusPreservesUnchangedValues(t *testing.T) {
	old := map[string]any{"device": map[string]any{"operating-system": map[string]any{"version": "18.6", "build-version": "22G86"}}, "softwareupdate": map[string]any{"failure-reason": "old"}}
	r := StatusReport{StatusItems: map[string]any{"device": map[string]any{"operating-system": map[string]any{"version": "18.7"}}, "softwareupdate": map[string]any{"failure-reason": nil}}}
	merged := MergeStatus(old, r)
	if statusString(merged, "device", "operating-system", "build-version") != "22G86" {
		t.Fatal("incremental update discarded unchanged status")
	}
	if _, exists := merged["softwareupdate"].(map[string]any)["failure-reason"]; exists {
		t.Fatal("null status failed to clear previous value")
	}
	r.FullReport = true
	merged = MergeStatus(old, r)
	if statusString(merged, "device", "operating-system", "build-version") != "" {
		t.Fatal("full report kept obsolete status")
	}
}

func TestDDMIncrementalArraysAndRemoval(t *testing.T) {
	old := []any{map[string]any{"identifier": "first", "valid": "valid"}, map[string]any{"identifier": "second", "valid": "valid"}}
	merged := mergeStatusArray(old, []any{map[string]any{"identifier": "first", "valid": "invalid"}})
	if len(merged) != 2 || merged[0].(map[string]any)["valid"] != "invalid" {
		t.Fatal("incremental array discarded existing records", merged)
	}
	merged = mergeStatusArray(merged, []any{map[string]any{"identifier": "first", "_removed": true}})
	if len(merged) != 1 || merged[0].(map[string]any)["identifier"] != "second" {
		t.Fatal("removed status retained", merged)
	}
}

func TestCatalogRejectsUnsupportedModelsExpiredReleasesAndWrongBuilds(t *testing.T) {
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	catalog := SoftwareCatalog{PublicAssetSets: map[string][]OSRelease{"iOS": {{Version: "18.7.1", Build: "22H100", PostingDate: "2026-09-01", ExpirationDate: "2026-10-01", SupportedDevices: []string{"iPhone16,1"}}}}}
	d := Device{Model: "iPhone16,1"}
	p := UpdatePolicy{TargetVersion: "18.7.1"}
	if !catalog.Supports(d, p, now) {
		t.Fatal("eligible update rejected")
	}
	p.TargetBuild = "bad"
	if catalog.Supports(d, p, now) {
		t.Fatal("wrong build accepted")
	}
	p.TargetBuild = ""
	d.Model = "iPad7,1"
	if catalog.Supports(d, p, now) {
		t.Fatal("wrong model accepted")
	}
	d.Model = "iPhone16,1"
	if catalog.Supports(d, p, now.AddDate(0, 2, 0)) {
		t.Fatal("expired release accepted")
	}
}
