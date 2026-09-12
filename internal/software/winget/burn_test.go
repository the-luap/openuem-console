package winget

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment"
)

func burnSnapshot() Snapshot {
	content := strings.ReplaceAll(string(msiSnapshot().Content), ".msi", ".exe")
	return fixtureSnapshot(strings.Replace(content, "InstallerType: wix", "InstallerType: burn", 1))
}

func burnTarget() BurnTarget {
	msi := msiTarget()
	return BurnTarget{Architecture: msi.Architecture, MinimumOS: msi.MinimumOS, Detection: enrollment.SoftwareDetection{Kind: "uninstall-key", UninstallKey: msi.Detection.ProductCode, RegistryView: "64", Version: msi.Detection.Version}}
}

func TestBurnPlanPinsSameBundleForBothOperationsAndExactRegistration(t *testing.T) {
	for _, architecture := range []string{"amd64", "arm64"} {
		for _, view := range []string{"32", "64"} {
			for _, operation := range []string{"install", "remove"} {
				target, index := burnTarget(), 0
				target.Architecture, target.Detection.RegistryView = architecture, view
				if architecture == "arm64" {
					index = 1
					target.Detection.UninstallKey = "{90000000-0000-4000-8000-000000000002}"
				}
				snapshot := fixtureSnapshot(strings.ReplaceAll(string(burnSnapshot().Content), ".exe", ".exe?token=private-burn"))
				plan, err := BurnPlan(snapshot, index, target, operation)
				if view == "32" {
					if err == nil {
						t.Fatal("emulated Burn registration view admitted")
					}
					continue
				}
				if err != nil || !plan.Valid() {
					t.Fatal("exact Burn plan", err)
				}
				args := []string{"/quiet", "/norestart"}
				if operation == "remove" {
					args = append([]string{"/uninstall"}, args...)
				}
				if plan.Kind != "windows-burn" || plan.Operation != operation || plan.Architecture != architecture || plan.Detection != target.Detection || plan.Identifier != snapshot.Coordinate.Identifier || plan.Version != snapshot.Coordinate.Version || plan.MinimumOS != target.MinimumOS || !slices.Equal(plan.Arguments, args) || len(plan.MSIProperties) != 0 || plan.Artifact.Format != "exe" || !strings.Contains(plan.Artifact.URL, "private-burn") || !slices.Equal(plan.SuccessCodes, []uint32{0}) || !slices.Equal(plan.RebootCodes, []uint32{3010}) {
					t.Fatal("Burn plan changed source or reviewed requirements")
				}
				other, err := BurnPlan(snapshot, index, target, map[string]string{"install": "remove", "remove": "install"}[operation])
				if err != nil || other.Artifact != plan.Artifact {
					t.Fatal("removal selected an unapproved binary", err)
				}
				if strings.Contains(fmt.Sprintf("%v %#v", plan, plan), "private-burn") {
					t.Fatal("Burn plan formatting exposed artifact credentials")
				}
			}
		}
	}
}

func TestBurnPlanPreservesRequirementsAndSwitchInheritance(t *testing.T) {
	for _, custom := range []string{"/norestart", "RestorePoint=0", "/uninstall"} {
		content := strings.Replace(string(burnSnapshot().Content), "Scope: machine", "Scope: machine\nInstallerSwitches:\n  Custom: "+custom, 1)
		content = strings.Replace(content, "- Architecture: x64", "- Architecture: x64\n  InstallerSwitches:\n    Silent: /quiet /norestart", 1)
		_, err := BurnPlan(fixtureSnapshot(content), 0, burnTarget(), "install")
		if (err == nil) != (custom == "/norestart") {
			t.Fatal("selected silent switch erased inherited custom behavior", err)
		}
		content = strings.Replace(content, "    Silent: /quiet /norestart", "    Silent: /quiet /norestart\n    Custom: /norestart", 1)
		if _, err := BurnPlan(fixtureSnapshot(content), 0, burnTarget(), "install"); err != nil {
			t.Fatal("explicit per-key override rejected", err)
		}
	}
	for _, root := range []string{"Dependencies:\n  PackageDependencies:\n  - PackageIdentifier: Other.Runtime\n", "InstallerSuccessCodes: [17]\n", "ExpectedReturnCodes:\n- InstallerReturnCode: 1641\n  ReturnResponse: rebootInitiated\n"} {
		content := strings.Replace(string(burnSnapshot().Content), "Installers:", root+"Installers:", 1)
		content = strings.Replace(content, "- Architecture: x64", "- Architecture: x64\n  Dependencies: {}\n  InstallerSuccessCodes: []\n  ExpectedReturnCodes: []", 1)
		if _, err := BurnPlan(fixtureSnapshot(content), 0, burnTarget(), "install"); !errors.Is(err, ErrInstaller) {
			t.Fatal("empty selected field erased a root requirement", err)
		}
	}
	content := strings.Replace(string(burnSnapshot().Content), "Scope: machine", "Scope: machine\nMinimumOSVersion: 10.0.26100.1\nAppsAndFeaturesEntries:\n- ProductCode: '{90000000-0000-4000-8000-000000000001}'\n  InstallerType: burn\n  DisplayVersion: 1.20.100", 1)
	target := burnTarget()
	target.Detection.Version = "1.20.100"
	plan, err := BurnPlan(fixtureSnapshot(content), 0, target, "install")
	if err != nil || plan.MinimumOS != "10.0.26100.1" || plan.Detection.Version != target.Detection.Version {
		t.Fatal("exact display version or stronger OS changed", err)
	}
	if _, err = BurnPlan(fixtureSnapshot(content), 0, burnTarget(), "install"); !errors.Is(err, ErrInstaller) {
		t.Fatal("package version substituted for displayed version", err)
	}
}

func TestBurnPlanRejectsAmbiguousOrUnsupportedExecution(t *testing.T) {
	for name, extra := range map[string]string{
		"agreement":              "Agreements:\n- AgreementLabel: Additional terms\n",
		"market":                 "Markets:\n  AllowedMarkets: [US]\n",
		"authentication":         "Authentication:\n  AuthenticationType: microsoftEntraId\n",
		"locale":                 "InstallerLocale: en-US\n",
		"future behavior":        "FutureBehavior: true\n",
		"scope elevation":        "ElevationRequirement: elevationProhibited\n",
		"platform":               "Platform: [Windows.Universal]\n",
		"interactive":            "InstallModes: [interactive]\n",
		"architecture exclusion": "UnsupportedOSArchitectures: [x64]\n",
		"automatic removal":      "UpgradeBehavior: uninstallPrevious\n",
		"location required":      "InstallLocationRequired: true\n",
		"explicit upgrade":       "RequireExplicitUpgrade: true\n",
		"switch substitution":    "InstallerSwitches:\n  Silent: /quiet ARG=<INSTALLPATH>\n",
		"unknown switch":         "InstallerSwitches:\n  FutureSwitch: x\n",
		"forced restart":         "InstallerSwitches:\n  Custom: /forcerestart\n",
		"upgrade action":         "InstallerSwitches:\n  Upgrade: /repair\n",
		"not silent":             "InstallerSwitches:\n  Silent: /norestart\n",
		"arbitrary command":      "InstallerSwitches:\n  Silent: /quiet & calc.exe\n",
		"nested MSI identity":    "AppsAndFeaturesEntries:\n- InstallerType: msi\n",
		"multiple identities":    "AppsAndFeaturesEntries:\n- DisplayName: First\n- DisplayName: Second\n",
		"conflicting identity":   "AppsAndFeaturesEntries:\n- ProductCode: '{90000000-0000-4000-8000-000000000002}'\n",
		"unknown ARP behavior":   "AppsAndFeaturesEntries:\n- FutureBehavior: present\n",
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := fixtureSnapshot(strings.Replace(string(burnSnapshot().Content), "Installers:", extra+"Installers:", 1))
			for _, operation := range []string{"install", "remove"} {
				if _, err := BurnPlan(snapshot, 0, burnTarget(), operation); !errors.Is(err, ErrInstaller) {
					t.Fatal("unsupported Burn behavior accepted", err)
				}
			}
		})
	}
	for _, kind := range []string{"exe", "inno", "nullsoft", "wix", "msi", "zip"} {
		snapshot := fixtureSnapshot(strings.Replace(string(burnSnapshot().Content), "InstallerType: burn", "InstallerType: "+kind, 1))
		if _, err := BurnPlan(snapshot, 0, burnTarget(), "install"); !errors.Is(err, ErrInstaller) {
			t.Fatal("another installer family treated as Burn", kind, err)
		}
	}
	for _, change := range []func(*BurnTarget){func(t *BurnTarget) { t.Architecture = "x86" }, func(t *BurnTarget) {
		t.Detection.Kind = "msi-product"
		t.Detection.ProductCode = t.Detection.UninstallKey
		t.Detection.UninstallKey = ""
		t.Detection.RegistryView = ""
	}, func(t *BurnTarget) { t.Detection.UninstallKey = "Other product" }, func(t *BurnTarget) { t.Detection.UninstallKey = "{90000000-0000-4000-8000-000000000002}" }, func(t *BurnTarget) { t.Detection.RegistryView = "" }, func(t *BurnTarget) { t.MinimumOS = "not-an-os" }} {
		target := burnTarget()
		change(&target)
		if _, err := BurnPlan(burnSnapshot(), 0, target, "install"); err == nil {
			t.Fatal("invalid Burn target accepted")
		}
	}
	for _, index := range []int{-1, 2, 256} {
		if _, err := BurnPlan(burnSnapshot(), index, burnTarget(), "install"); err == nil {
			t.Fatal("unselected installer accepted")
		}
	}
	if _, err := BurnPlan(burnSnapshot(), 0, burnTarget(), "repair"); err == nil {
		t.Fatal("unreviewed Burn operation accepted")
	}
	for _, replacement := range [][2]string{{"Scope: machine", "Scope: user"}, {"https://example.invalid/editor.exe", "http://example.invalid/editor.exe"}, {".exe", ".msi"}} {
		snapshot := fixtureSnapshot(strings.ReplaceAll(string(burnSnapshot().Content), replacement[0], replacement[1]))
		if _, err := BurnPlan(snapshot, 0, burnTarget(), "install"); err == nil {
			t.Fatal("invalid Burn scope or artifact accepted")
		}
	}
}

func TestInstallerSwitchesDoNotNormalizeNonWindowsSeparators(t *testing.T) {
	for _, burn := range []bool{false, true} {
		snapshot := msiSnapshot()
		if burn {
			snapshot = burnSnapshot()
		}
		snapshot = fixtureSnapshot(strings.Replace(string(snapshot.Content), "Scope: machine", "Scope: machine\nInstallerSwitches:\n  Silent: /QUİET /norestart", 1))
		var err error
		if burn {
			_, err = BurnPlan(snapshot, 0, burnTarget(), "install")
		} else {
			_, err = MSIPlan(snapshot, 0, msiTarget(), "install")
		}
		if err == nil {
			t.Fatal("Unicode case folding changed an unknown token into a quiet flag")
		}
	}
	for _, separator := range []string{"\n", "\r", "\v", "\f", "\u00a0", "\u2003", "\u2028"} {
		for _, burn := range []bool{false, true} {
			snapshot := msiSnapshot()
			if burn {
				snapshot = burnSnapshot()
			}
			content := strings.Replace(string(snapshot.Content), "Scope: machine", "Scope: machine\nInstallerSwitches:\n  Silent: "+fmt.Sprintf("%q", "/quiet"+separator+"/norestart"), 1)
			var err error
			if burn {
				_, err = BurnPlan(fixtureSnapshot(content), 0, burnTarget(), "install")
			} else {
				_, err = MSIPlan(fixtureSnapshot(content), 0, msiTarget(), "install")
			}
			if err == nil {
				t.Fatal("non-Windows whitespace changed into command separators")
			}
		}
		content := strings.Replace(string(msiSnapshot().Content), "Scope: machine", "Scope: machine\nInstallerSwitches:\n  Custom: "+fmt.Sprintf("%q", separator+"ALLUSERS=1"), 1)
		if _, err := MSIPlan(fixtureSnapshot(content), 0, msiTarget(), "install"); err == nil {
			t.Fatal("non-Windows custom prefix ignored")
		}
	}
	for _, silent := range []string{"/quiet /norestart", " /Q\t/NORESTART\t", "\t/QUIET "} {
		for _, burn := range []bool{false, true} {
			snapshot := msiSnapshot()
			if burn {
				snapshot = burnSnapshot()
			}
			snapshot = fixtureSnapshot(strings.Replace(string(snapshot.Content), "Scope: machine", "Scope: machine\nInstallerSwitches:\n  Silent: "+fmt.Sprintf("%q", silent), 1))
			var err error
			if burn {
				_, err = BurnPlan(snapshot, 0, burnTarget(), "install")
			} else {
				_, err = MSIPlan(snapshot, 0, msiTarget(), "install")
			}
			if err != nil {
				t.Fatal("literal space/tab quiet flags rejected", err)
			}
		}
	}
}

func FuzzBurnPlan(f *testing.F) {
	f.Add(string(burnSnapshot().Content), 0)
	f.Add(fixtureManifest, 0)
	f.Fuzz(func(t *testing.T, content string, index int) {
		for _, operation := range []string{"install", "remove"} {
			plan, err := BurnPlan(fixtureSnapshot(content), index, burnTarget(), operation)
			if err == nil && (!plan.Valid() || plan.Operation != operation || plan.Kind != "windows-burn" || plan.Detection.Kind != "uninstall-key" || plan.Detection.RegistryView != "64" || plan.Artifact.Format != "exe") {
				t.Fatal("parser emitted an invalid or differently scoped Burn plan")
			}
		}
	})
}
