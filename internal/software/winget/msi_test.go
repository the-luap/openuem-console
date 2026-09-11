package winget

import (
	"errors"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment"
)

func msiSnapshot() Snapshot {
	content := strings.Replace(fixtureManifest, "UnknownFutureBehavior:\n  MustRemainVisible: true\n", "", 1)
	content = strings.Replace(content, "- Architecture: arm64\n  InstallerUrl: https://example.invalid/editor-arm64.msi", "- Architecture: arm64\n  InstallerUrl: https://example.invalid/editor-arm64.msi\n  InstallerSha256: "+strings.Repeat("a", 64)+"\n  ProductCode: '{90000000-0000-4000-8000-000000000002}'", 1)
	return fixtureSnapshot(content)
}

func msiTarget() MSITarget {
	return MSITarget{Architecture: "amd64", MinimumOS: "10.0.22000", Detection: enrollment.SoftwareDetection{Kind: "msi-product", ProductCode: "{90000000-0000-4000-8000-000000000001}", Version: "1.20.0"}}
}

func TestMSIPlanBindsSelectedArchitectureAndExactNativeDetection(t *testing.T) {
	for _, architecture := range []string{"amd64", "arm64"} {
		for _, operation := range []string{"install", "remove"} {
			target, index := msiTarget(), 0
			if architecture == "arm64" {
				target.Architecture = architecture
				target.Detection.ProductCode = "{90000000-0000-4000-8000-000000000002}"
				index = 1
			}
			plan, err := MSIPlan(msiSnapshot(), index, target, operation)
			if err != nil || !plan.Valid() {
				t.Fatalf("%s %s: %v", architecture, operation, err)
			}
			if plan.Kind != "windows-msi" || plan.Operation != operation || plan.Architecture != architecture || plan.Detection != target.Detection || plan.Identifier != fixtureCoordinate.Identifier || plan.Version != fixtureCoordinate.Version || plan.MinimumOS != target.MinimumOS || len(plan.MSIProperties) != 0 || len(plan.Arguments) != 0 {
				t.Fatal("plan changed exact intent")
			}
			if operation == "install" {
				if plan.Artifact.URL == "" || plan.Artifact.SHA256 != strings.ToLower(plan.Artifact.SHA256) {
					t.Fatal("installer hash not retained")
				}
			} else if plan.Artifact != (enrollment.SoftwareArtifact{}) {
				t.Fatal("MSI removal received executable artifact")
			}
		}
	}
	for _, minimum := range []string{"6.1.7601.0", "10.0.19041.0", "10.0.22000", "10.0.26100.1"} {
		snapshot := msiSnapshot()
		content := strings.Replace(string(snapshot.Content), "Scope: machine", "Scope: machine\nMinimumOSVersion: "+minimum, 1)
		plan, err := MSIPlan(fixtureSnapshot(content), 0, msiTarget(), "install")
		if err != nil {
			t.Fatal(err)
		}
		want := "10.0.22000"
		if minimum == "10.0.26100.1" {
			want = minimum
		}
		if plan.MinimumOS != want {
			t.Fatal("source weakened OS approval")
		}
	}
	// An explicit displayed version is not interchangeable with a package version.
	content := strings.Replace(string(msiSnapshot().Content), "Scope: machine", "Scope: machine\nAppsAndFeaturesEntries:\n- DisplayVersion: 1.20.100\n  ProductCode: '{90000000-0000-4000-8000-000000000001}'", 1)
	target := msiTarget()
	target.Detection.Version = "1.20.100"
	if _, err := MSIPlan(fixtureSnapshot(content), 0, target, "install"); err != nil {
		t.Fatal(err)
	}
	if _, err := MSIPlan(fixtureSnapshot(content), 0, msiTarget(), "install"); !errors.Is(err, ErrInstaller) {
		t.Fatal("different display version accepted")
	}
}

func TestMSIPlanPreservesSwitchInheritance(t *testing.T) {
	for _, custom := range []string{"ALLUSERS=1", "INSTALLDIR=Different", "REBOOT=Force"} {
		content := strings.Replace(string(msiSnapshot().Content), "Scope: machine", "Scope: machine\nInstallerSwitches:\n  Custom: "+custom+"\n  InstallLocation: 'INSTALLDIR=\"<INSTALLPATH>\"'", 1)
		content = strings.Replace(content, "- Architecture: x64", "- Architecture: x64\n  InstallerSwitches:\n    Silent: /qn /norestart", 1)
		_, err := MSIPlan(fixtureSnapshot(content), 0, msiTarget(), "install")
		if (err == nil) != (custom == "ALLUSERS=1") {
			t.Fatalf("inherited custom behavior: %v", err)
		}
		// A real per-key override replaces Custom, while other keys survive.
		content = strings.Replace(content, "    Silent: /qn /norestart", "    Silent: /qn /norestart\n    Custom: ALLUSERS=1", 1)
		if _, err := MSIPlan(fixtureSnapshot(content), 0, msiTarget(), "install"); err != nil {
			t.Fatal("exact per-key override rejected", err)
		}
	}
	for _, root := range []string{"Dependencies:\n  PackageDependencies:\n  - PackageIdentifier: Example.Dependency\n", "ExpectedReturnCodes:\n- InstallerReturnCode: 1641\n  ReturnResponse: rebootInitiated\n", "InstallerSuccessCodes: [17]\n"} {
		content := strings.Replace(string(msiSnapshot().Content), "Installers:", root+"Installers:", 1)
		content = strings.Replace(content, "- Architecture: x64", "- Architecture: x64\n  Dependencies: {}\n  ExpectedReturnCodes: []\n  InstallerSuccessCodes: []", 1)
		if _, err := MSIPlan(fixtureSnapshot(content), 0, msiTarget(), "install"); !errors.Is(err, ErrInstaller) {
			t.Fatal("empty override erased inherited requirements")
		}
	}
}

func TestMSIPlanRejectsUnsupportedOrConflictingRequirements(t *testing.T) {
	for name, extra := range map[string]string{
		"dependencies":              "Dependencies:\n  WindowsFeatures: [NetFx3]\n",
		"custom returns":            "InstallerSuccessCodes: [17]\n",
		"return action":             "ExpectedReturnCodes:\n- InstallerReturnCode: 1641\n  ReturnResponse: rebootInitiated\n",
		"market":                    "Markets:\n  AllowedMarkets: [US]\n",
		"agreements":                "Agreements:\n- AgreementLabel: Additional agreement\n",
		"authentication":            "Authentication:\n  AuthenticationType: microsoftEntraId\n",
		"locale":                    "InstallerLocale: de-DE\n",
		"unknown":                   "FutureBehavior: must-not-disappear\n",
		"unsupported host":          "UnsupportedOSArchitectures: [x64]\n",
		"invalid host exclusion":    "UnsupportedOSArchitectures: [other]\n",
		"wrong platform":            "Platform: [Windows.Universal]\n",
		"interactive only":          "InstallModes: [interactive]\n",
		"unknown mode":              "InstallModes: [silent, unknown]\n",
		"required location":         "InstallLocationRequired: true\n",
		"aborts terminal":           "InstallerAbortsTerminal: true\n",
		"blocks downloads":          "DownloadCommandProhibited: true\n",
		"warning":                   "DisplayInstallWarnings: true\n",
		"wrong flag type":           "RequireExplicitUpgrade: 'false'\n",
		"explicit upgrade":          "RequireExplicitUpgrade: true\n",
		"automatic removal":         "UpgradeBehavior: uninstallPrevious\n",
		"elevation prohibited":      "ElevationRequirement: elevationProhibited\n",
		"arbitrary silent switches": "InstallerSwitches:\n  Silent: /qn TRANSFORMS=https://example.invalid/transform\n",
		"empty silent switches":     "InstallerSwitches:\n  Silent: ''\n",
		"not actually silent":       "InstallerSwitches:\n  Silent: /norestart\n",
		"upgrade switches":          "InstallerSwitches:\n  Upgrade: REINSTALL=ALL\n",
		"unknown switches":          "InstallerSwitches:\n  Unknown: value\n",
		"switch type":               "InstallerSwitches: [a,b]\n",
		"conflicting ARP":           "AppsAndFeaturesEntries:\n- ProductCode: '{90000000-0000-4000-8000-000000000002}'\n",
		"multiple products":         "AppsAndFeaturesEntries:\n- DisplayName: One\n- DisplayName: Two\n",
		"ARP installer type":        "AppsAndFeaturesEntries:\n- InstallerType: exe\n",
		"unknown ARP behavior":      "AppsAndFeaturesEntries:\n- ExtraBehavior: value\n",
		"bad OS":                    "MinimumOSVersion: 10.0.01\n",
		"future OS":                 "MinimumOSVersion: 11.0.10000\n",
	} {
		t.Run(name, func(t *testing.T) {
			content := strings.Replace(string(msiSnapshot().Content), "Installers:", extra+"Installers:", 1)
			if _, err := MSIPlan(fixtureSnapshot(content), 0, msiTarget(), "install"); !errors.Is(err, ErrInstaller) {
				t.Fatalf("unsupported requirement accepted: %v", err)
			}
		})
	}
	for name, replace := range map[string][2]string{
		"user scope": {"Scope: machine", "Scope: user"}, "unknown scope": {"Scope: machine", "Scope: other"}, "missing scope": {"Scope: machine\n", ""},
		"exe": {"InstallerType: wix", "InstallerType: exe"}, "archive": {"InstallerType: wix", "InstallerType: zip"},
		"insecure artifact":   {"https://example.invalid/editor.msi", "http://example.invalid/editor.msi"},
		"credential artifact": {"https://example.invalid/editor.msi", "https://user:password@example.invalid/editor.msi"},
		"wrong format":        {"https://example.invalid/editor.msi", "https://example.invalid/editor.exe"},
		"digest":              {"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", "not-a-hash"},
		"product case":        {"000000000001}", "000000000003}"},
	} {
		t.Run(name, func(t *testing.T) {
			content := strings.Replace(string(msiSnapshot().Content), replace[0], replace[1], 1)
			if _, err := MSIPlan(fixtureSnapshot(content), 0, msiTarget(), "remove"); !errors.Is(err, ErrInstaller) {
				t.Fatal("invalid source entered removal plan")
			}
		})
	}
	for _, index := range []int{-1, 1, 2} {
		if _, err := MSIPlan(msiSnapshot(), index, msiTarget(), "install"); !errors.Is(err, ErrInstaller) {
			t.Fatal("wrong selected installer accepted")
		}
	}
	for _, operation := range []string{"", "upgrade", "repair"} {
		if _, err := MSIPlan(msiSnapshot(), 0, msiTarget(), operation); !errors.Is(err, ErrInstaller) {
			t.Fatal("unreviewed operation accepted")
		}
	}
	target := msiTarget()
	target.Architecture = "386"
	if _, err := MSIPlan(msiSnapshot(), 0, target, "install"); !errors.Is(err, ErrInstaller) {
		t.Fatal("unsupported agent architecture accepted")
	}
}

func FuzzMSIPlan(f *testing.F) {
	f.Add(string(msiSnapshot().Content), 0)
	f.Add(fixtureManifest, 0)
	f.Fuzz(func(t *testing.T, content string, index int) {
		if len(content) > MaxManifestBytes {
			t.Skip()
		}
		for _, operation := range []string{"install", "remove"} {
			plan, err := MSIPlan(fixtureSnapshot(content), index, msiTarget(), operation)
			if err == nil && (!plan.Valid() || plan.Operation != operation || plan.Architecture != "amd64" || plan.Detection != msiTarget().Detection) {
				t.Fatal("accepted plan escaped original intent")
			}
		}
	})
}
