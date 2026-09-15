package apple

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"howett.net/plist"
)

func testMacAppPackage() MacAppPackageInput {
	return MacAppPackageInput{Name: "Example Editor", Identifier: "com.example.Editor", Version: "42.0", Architecture: "universal", MinimumOS: "11.0", SHA256: strings.Repeat("a", 64), SourceURL: "https://packages.example.test/Editor.pkg?token=not-for-pages", SingleApp: true}
}

func TestMacAppManifestPinsArtifactAndManagementOptions(t *testing.T) {
	p := testMacAppPackage()
	args, err := macAppInstallArguments(p, MacAppInstallOptions{RemoveOnUnenroll: true, TakeOver: true})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := plist.Marshal(args, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		InstallAsManaged      bool
		ManagementFlags       int
		ChangeManagementState string
		Manifest              struct {
			Items []struct {
				Assets []struct {
					Kind   string `plist:"kind"`
					URL    string `plist:"url"`
					SHA256 string `plist:"sha256"`
				} `plist:"assets"`
				Metadata struct {
					Kind       string `plist:"kind"`
					Identifier string `plist:"bundle-identifier"`
					Version    string `plist:"bundle-version"`
				} `plist:"metadata"`
			} `plist:"items"`
		}
	}
	if _, err = plist.Unmarshal(wire, &decoded); err != nil || !decoded.InstallAsManaged || decoded.ManagementFlags != 1 || decoded.ChangeManagementState != "Managed" || len(decoded.Manifest.Items) != 1 {
		t.Fatal("invalid managed installation envelope", err)
	}
	item := decoded.Manifest.Items[0]
	if item.Metadata.Kind != "software" || item.Metadata.Identifier != p.Identifier || item.Metadata.Version != p.Version || len(item.Assets) != 1 || item.Assets[0].Kind != "software-package" || item.Assets[0].SHA256 != p.SHA256 || item.Assets[0].URL != p.SourceURL {
		t.Fatal("artifact identity or digest was lost")
	}
	args, err = macAppInstallArguments(p, MacAppInstallOptions{})
	if err != nil || args["ManagementFlags"] != nil || args["ChangeManagementState"] != nil || args["ManifestURL"] != nil {
		t.Fatal("default install unexpectedly changes ownership or removal policy")
	}
	public, err := json.Marshal(p)
	if err != nil || bytes.Contains(public, []byte("not-for-pages")) || bytes.Contains(public, []byte("SourceURL")) {
		t.Fatal("source credential entered JSON")
	}
}

func TestMacAppPackageValidation(t *testing.T) {
	for name, change := range map[string]func(*MacAppPackageInput){
		"HTTP":                       func(p *MacAppPackageInput) { p.SourceURL = "http://example.test/a.pkg" },
		"userinfo":                   func(p *MacAppPackageInput) { p.SourceURL = "https://user:secret@example.test/a.pkg" },
		"fragment":                   func(p *MacAppPackageInput) { p.SourceURL += "#secret" },
		"port":                       func(p *MacAppPackageInput) { p.SourceURL = "https://example.test:65536/a.pkg" },
		"empty port":                 func(p *MacAppPackageInput) { p.SourceURL = "https://example.test:/a.pkg" },
		"unescaped space":            func(p *MacAppPackageInput) { p.SourceURL = "https://example.test/an app.pkg" },
		"opaque":                     func(p *MacAppPackageInput) { p.SourceURL = "https:a.pkg" },
		"missing path":               func(p *MacAppPackageInput) { p.SourceURL = "https://example.test" },
		"oversized URL":              func(p *MacAppPackageInput) { p.SourceURL += strings.Repeat("a", 8192) },
		"identifier":                 func(p *MacAppPackageInput) { p.Identifier = "com.example.*" },
		"empty identifier component": func(p *MacAppPackageInput) { p.Identifier = "com..example" },
		"version":                    func(p *MacAppPackageInput) { p.Version = "" },
		"display version is opaque":  func(p *MacAppPackageInput) { p.Version = "1.0\n2.0" },
		"invalid name":               func(p *MacAppPackageInput) { p.Name = "\xff" },
		"architecture":               func(p *MacAppPackageInput) { p.Architecture = "all" },
		"unsupported OS":             func(p *MacAppPackageInput) { p.MinimumOS = "10.15" },
		"malformed OS":               func(p *MacAppPackageInput) { p.MinimumOS = "11.x" },
		"multiple apps on older OS":  func(p *MacAppPackageInput) { p.SingleApp = false },
		"digest":                     func(p *MacAppPackageInput) { p.SHA256 = strings.Repeat("x", 64) },
		"noncanonical digest":        func(p *MacAppPackageInput) { p.SHA256 = strings.Repeat("A", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			p := testMacAppPackage()
			change(&p)
			if p.Validate() == nil {
				t.Fatal("invalid package accepted")
			}
		})
	}
	p := testMacAppPackage()
	p.SingleApp, p.MinimumOS, p.Architecture, p.Version = false, "14.0", "arm64", "2026.09.4-beta"
	if err := p.Validate(); err != nil {
		t.Fatal("supported package rejected", err)
	}
}

func TestMacAppObservationsDistinguishManagementAndVersion(t *testing.T) {
	id := "com.example.Editor"
	for _, state := range []string{"Installing", "Managed", "Failed", "ManagedButUninstalled", "Unknown", "UserInstalledApp", "FutureStatus"} {
		got, err := macAppManagedObservation(map[string]any{id: map[string]any{"Status": state}}, id)
		if err != nil || (got.State == "managed") != (state == "Managed") {
			t.Fatal("management was inferred from a nonterminal status", state, got, err)
		}
	}
	for _, tc := range []struct {
		name  string
		items []any
		state string
	}{
		{"absent", []any{}, "absent"},
		{"exact version", []any{map[string]any{"Identifier": id, "Version": "42.0", "ShortVersion": "1.2"}}, "installed"},
		{"missing Mac identifier", []any{map[string]any{"Name": "Editor", "Version": "42.0"}}, "unknown"},
		{"short version is insufficient", []any{map[string]any{"Identifier": id, "ShortVersion": "42.0"}}, "unknown"},
		{"downloading", []any{map[string]any{"Identifier": id, "Version": "42.0", "Installing": true}}, "pending"},
		{"download failed", []any{map[string]any{"Identifier": id, "Version": "42.0", "DownloadFailed": true}}, "pending"},
		{"duplicate bundle", []any{map[string]any{"Identifier": id, "Version": "42.0"}, map[string]any{"Identifier": id, "Version": "41.0"}}, "conflict"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := macAppInstalledObservation(tc.items, id)
			if err != nil || got.State != tc.state || (got.State == "installed" && got.Version != "42.0") {
				t.Fatal(got, err)
			}
		})
	}
	if _, err := macAppInstalledObservation([]any{map[string]any{"Identifier": id, "Version": "42.0", "Installing": "false"}}, id); err == nil {
		t.Fatal("string flag accepted as a boolean")
	}
	if _, err := macAppManagedObservation(nil, id); err == nil {
		t.Fatal("missing response treated as absence")
	}
}

func FuzzMacAppPackageURL(f *testing.F) {
	f.Add("https://packages.example.test/a.pkg?token=x")
	f.Add("https://user@example.test/a.pkg")
	f.Fuzz(func(t *testing.T, source string) {
		p := testMacAppPackage()
		p.SourceURL = source
		if p.Validate() != nil {
			return
		}
		args, err := macAppInstallArguments(p, MacAppInstallOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = plist.Marshal(args, plist.XMLFormat); err != nil {
			t.Fatal(err)
		}
	})
}
