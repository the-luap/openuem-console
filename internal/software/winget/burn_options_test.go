package winget

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBurnOptionsPreserveExactNativeChoiceAndPrivateArtifact(t *testing.T) {
	snapshot := fixtureSnapshot(strings.ReplaceAll(string(burnSnapshot().Content), ".exe", ".exe?token=private-source"))
	target := burnTarget()
	options, err := BurnOptions(snapshot, target)
	if err != nil || len(options) != 1 || options[0].Kind != "windows-burn" || options[0].Index != 0 || options[0].DownloadHost != "example.invalid" {
		t.Fatal("exact native Burn choice unavailable", err)
	}
	plan, err := BurnPlan(snapshot, options[0].Index, target, "install")
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := plan.Digest()
	if options[0].PlanDigest != digest || options[0].SHA256 != plan.Artifact.SHA256 || options[0].MinimumOS != plan.MinimumOS {
		t.Fatal("review changed the approved Burn plan")
	}
	wire, _ := json.Marshal(options)
	if strings.Contains(string(wire), "private-") || strings.Contains(string(wire), "https://") || strings.Contains(string(wire), "/quiet") {
		t.Fatal("review exposed artifact credentials or execution arguments")
	}
	target.Architecture = "arm64"
	target.Detection.UninstallKey = "{90000000-0000-4000-8000-000000000002}"
	options, err = BurnOptions(snapshot, target)
	if err != nil || len(options) != 1 || options[0].Index != 1 {
		t.Fatal("ARM64 choice did not preserve its manifest index", err)
	}
	target.Detection.RegistryView = "32"
	options, err = BurnOptions(snapshot, target)
	if err != nil || len(options) != 0 {
		t.Fatal("review offered an emulated registration view", err)
	}
	options, err = BurnOptions(msiSnapshot(), burnTarget())
	if err != nil || len(options) != 0 {
		t.Fatal("MSI manifest was inferred to be a Burn bundle", err)
	}
}
