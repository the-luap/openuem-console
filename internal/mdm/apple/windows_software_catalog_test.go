package apple

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func testWindowsSoftware(kind string) WindowsSoftwareInput {
	p := WindowsSoftwareInput{Name: "Owned Windows package", Identifier: "Vendor.Product", Version: "1.2.3", Kind: kind, Architecture: "x86_64", MinimumOS: "10.0.26100", SuccessCodes: []uint32{0}, Detection: WindowsSoftwareDetection{Kind: "msi-product", ProductCode: "{AABBCCDD-0000-4000-8000-000000000001}", Version: "1.2.3"}}
	if kind != "windows-winget" {
		p.SHA256 = strings.Repeat("a", 64)
		p.RebootCodes = []uint32{3010}
	}
	if kind == "windows-msi" {
		p.Execution = WindowsSoftwareExecution{SourceURL: "https://packages.example.test/owned.msi?token=private-download", MSIProperties: map[string]string{"LICENSEKEY": "private-license"}}
	}
	if kind == "windows-exe" {
		p.Execution = WindowsSoftwareExecution{SourceURL: "https://packages.example.test/owned.exe?token=private-download", InstallArguments: []string{"/silent", "private-install-argument"}, UninstallURL: "https://packages.example.test/remove.exe?token=private-removal", UninstallSHA256: strings.Repeat("b", 64), UninstallArguments: []string{"/silent", "private-remove-argument"}}
	}
	if kind == "windows-burn" {
		p.Detection = WindowsSoftwareDetection{Kind: "uninstall-key", UninstallKey: p.Detection.ProductCode, RegistryView: "64", Version: p.Detection.Version}
		p.Execution = WindowsSoftwareExecution{SourceURL: "https://packages.example.test/owned.exe?token=private-download", InstallArguments: []string{"/quiet", "/norestart"}, UninstallURL: "https://packages.example.test/owned.exe?token=private-download", UninstallSHA256: p.SHA256, UninstallArguments: []string{"/uninstall", "/quiet", "/norestart"}}
	}
	return p
}

func TestWindowsSoftwareDefinitionAndCredentialProjection(t *testing.T) {
	for _, kind := range []string{"windows-winget", "windows-msi", "windows-exe", "windows-burn"} {
		p := testWindowsSoftware(kind)
		if err := p.Validate(); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		public, _ := json.Marshal(p.Metadata())
		input, _ := json.Marshal(p)
		if bytes.Contains(public, []byte("private-")) || bytes.Contains(input, []byte("private-")) || bytes.Contains(public, []byte("example.test")) {
			t.Fatal("credential entered public projection")
		}
		canonical, err := p.canonical()
		if err != nil || (kind != "windows-winget" && !bytes.Contains(canonical, []byte("private-download"))) {
			t.Fatal("encrypted definition lost source intent", err)
		}
	}
	for _, change := range []func(*WindowsSoftwareInput){
		func(p *WindowsSoftwareInput) { p.Execution.SourceURL = "http://packages.example.test/a.msi" },
		func(p *WindowsSoftwareInput) {
			p.Execution.SourceURL = "https://user:secret@packages.example.test/a.msi"
		},
		func(p *WindowsSoftwareInput) { p.Execution.SourceURL = "https://packages.example.test/a.msi#token" },
		func(p *WindowsSoftwareInput) { p.Execution.SourceURL = "https://packages.example.test:99999/a.msi" },
		func(p *WindowsSoftwareInput) { p.Execution.SourceURL = "https://packages.example.test/a.exe" },
		func(p *WindowsSoftwareInput) { p.Execution.MSIProperties["REBOOT"] = "Force" },
		func(p *WindowsSoftwareInput) { p.Execution.MSIProperties["TRANSFORMS"] = "unapproved.mst" },
		func(p *WindowsSoftwareInput) { p.Execution.MSIProperties["LICENSEKEY"] = "private\nvalue" },
		func(p *WindowsSoftwareInput) { p.Execution.MSIProperties["LICENSEKEY"] = `private"value` },
		func(p *WindowsSoftwareInput) { p.Detection.ProductCode = strings.ToLower(p.Detection.ProductCode) },
		func(p *WindowsSoftwareInput) { p.Detection.RegistryView = "64" },
		func(p *WindowsSoftwareInput) { p.SuccessCodes = []uint32{0, 3010} },
		func(p *WindowsSoftwareInput) { p.RebootCodes = []uint32{} },
		func(p *WindowsSoftwareInput) { p.Architecture = "universal" },
		func(p *WindowsSoftwareInput) { p.SHA256 = strings.Repeat("A", 64) },
		func(p *WindowsSoftwareInput) { p.Execution.InstallArguments = []string{"/quiet"} },
		func(p *WindowsSoftwareInput) { p.Kind = "unsupported" },
	} {
		p := testWindowsSoftware("windows-msi")
		change(&p)
		if err := p.Validate(); !errors.Is(err, ErrWindowsSoftware) {
			t.Fatalf("invalid approval accepted: %v", err)
		}
	}
	p := testWindowsSoftware("windows-winget")
	p.Identifier = "Vendor.Product --all"
	if p.Validate() == nil {
		t.Fatal("ambiguous WinGet coordinate accepted")
	}
	p = testWindowsSoftware("windows-exe")
	p.Detection = WindowsSoftwareDetection{Kind: "uninstall-key", UninstallKey: "Vendor Product", RegistryView: "32", Version: "1.2.3"}
	if p.Validate() != nil {
		t.Fatal("exact machine uninstall-key detection rejected")
	}
	p.Detection.UninstallKey = `..\other`
	if p.Validate() == nil {
		t.Fatal("arbitrary registry path accepted")
	}
}

func windowsSoftwareStore(t *testing.T) (*Store, *access.Store) {
	t.Helper()
	return windowsSoftwareStoreBeforeMigration(t, "")
}

func windowsSoftwareStoreBeforeMigration(t *testing.T, before string) (*Store, *access.Store) {
	t.Helper()
	s := testStoreBeforeMigration(t, before)
	if _, err := s.db.Exec(`CREATE TABLE users(uid TEXT PRIMARY KEY);INSERT INTO users VALUES('admin'),('reader'),('operator'),('second-admin')`); err != nil {
		t.Fatal(err)
	}
	permissions, err := access.NewStore(s.db)
	if err != nil {
		t.Fatal(err)
	}
	if err = permissions.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = permissions.Bootstrap(t.Context(), "admin"); err != nil {
		t.Fatal(err)
	}
	for actor, role := range map[string]access.Role{"reader": access.Viewer, "operator": access.Operator, "second-admin": access.TenantAdmin} {
		scope := access.Scope{TenantID: 1, SiteID: 1}
		if actor == "second-admin" {
			scope.SiteID = 0
		}
		if err = permissions.ReplaceGrants(t.Context(), "admin", actor, 0, []access.Grant{{Role: role, Scope: scope}}); err != nil {
			t.Fatal(err)
		}
	}
	return s, permissions
}

func TestWindowsSoftwareApprovalIsImmutableEncryptedAndIdempotent(t *testing.T) {
	s, permissions := windowsSoftwareStore(t)
	ctx, scope := t.Context(), Scope{TenantID: 1}
	input, request := testWindowsSoftware("windows-msi"), uuid.NewString()
	for _, actor := range []string{"reader", "operator", "unknown"} {
		if _, err := s.PublishWindowsSoftware(ctx, scope, request, input, actor, permissions); !errors.Is(err, access.ErrDenied) {
			t.Fatal("publisher authority bypass", actor, err)
		}
	}
	const workers = 6
	ids := make(chan string, workers)
	errs := make(chan error, workers)
	var work sync.WaitGroup
	for range workers {
		work.Add(1)
		go func() {
			defer work.Done()
			v, err := s.PublishWindowsSoftware(ctx, scope, request, input, "admin", permissions)
			if err != nil {
				errs <- err
				return
			}
			ids <- v.ID
		}()
	}
	work.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	version := ""
	for id := range ids {
		if version != "" && id != version {
			t.Fatal("concurrent retry approved another revision")
		}
		version = id
	}
	if version == "" {
		t.Fatal("approval missing")
	}
	var sealed []byte
	var count int
	if err := s.db.QueryRow(`SELECT encrypted_definition FROM uem_software_versions WHERE id=$1`, version).Scan(&sealed); err != nil || bytes.Contains(sealed, []byte("private-")) {
		t.Fatal("plaintext execution definition", err)
	}
	for _, purpose := range []string{secretPurpose(2, version, "windows_software_definition"), secretPurpose(1, uuid.NewString(), "windows_software_definition"), secretPurpose(1, version, "software_url")} {
		if _, err := s.secrets.open(sealed, purpose); err == nil {
			t.Fatal("definition decrypted under another binding")
		}
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE action='software.windows.version.publish'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("replayed publication audit", count, err)
	}
	if _, err := s.PublishWindowsSoftware(ctx, scope, request, input, "second-admin", permissions); !errors.Is(err, ErrConflict) {
		t.Fatal("request transferred to another actor", err)
	}
	changed := input
	changed.Version = "2.0"
	if _, err := s.PublishWindowsSoftware(ctx, scope, request, changed, "admin", permissions); !errors.Is(err, ErrConflict) {
		t.Fatal("request intent changed", err)
	}
	for _, query := range []string{`UPDATE uem_software_versions SET windows_metadata='{}' WHERE id=$1`, `UPDATE uem_software_versions SET encrypted_definition=encrypted_definition||'x'::bytea WHERE id=$1`, `UPDATE uem_software_versions SET approval_request_id=gen_random_uuid() WHERE id=$1`, `UPDATE uem_software_versions SET version='2.0' WHERE id=$1`} {
		if _, err := s.db.Exec(query, version); err == nil {
			t.Fatal("approved definition mutated")
		}
	}
	v, err := s.ReadSoftwareVersion(ctx, Scope{TenantID: 1, SiteID: 1}, version, "reader", permissions)
	if err != nil || v.Platform != "windows" || v.Kind != "windows-msi" || v.Windows.Detection.ProductCode != input.Detection.ProductCode {
		t.Fatal("reader projection", v, err)
	}
	public, _ := json.Marshal(v)
	if bytes.Contains(public, []byte("private-")) || bytes.Contains(public, []byte("example.test")) {
		t.Fatal("reader received source/parameters")
	}
	if _, err = s.ReadSoftwareVersion(ctx, Scope{TenantID: 2}, version, "reader", permissions); !errors.Is(err, access.ErrDenied) {
		t.Fatal("foreign reader accepted", err)
	}
	if err = s.WithdrawSoftwareVersion(ctx, scope, version, "admin", permissions); err != nil {
		t.Fatal(err)
	}
	if err = s.WithdrawSoftwareVersion(ctx, scope, version, "admin", permissions); err != nil {
		t.Fatal("withdrawal retry failed", err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE action='software.windows.version.withdraw' AND resource_id=$1`, version).Scan(&count); err != nil || count != 1 {
		t.Fatal("Windows withdrawal audit missing or repeated", count, err)
	}
	v, err = s.PublishWindowsSoftware(ctx, scope, request, input, "admin", permissions)
	if err != nil || v.WithdrawnAt == nil || v.ID != version {
		t.Fatal("replay reapproved withdrawn revision", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, _, err = s.macAppArtifactTx(ctx, tx, 1, version); !errors.Is(err, ErrNotFound) {
		t.Fatal("Windows artifact entered Mac adapter", err)
	}
}

func TestWindowsSoftwareCatalogReadsAndPublicationRequireAuditCommit(t *testing.T) {
	s, permissions := windowsSoftwareStore(t)
	ctx, scope := t.Context(), Scope{TenantID: 1}
	for _, kind := range []string{"windows-winget", "windows-msi", "windows-exe"} {
		if _, err := s.PublishWindowsSoftware(ctx, scope, uuid.NewString(), testWindowsSoftware(kind), "admin", permissions); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.PublishMacAppPackage(ctx, scope, testMacAppPackage(), "admin", permissions); err != nil {
		t.Fatal(err)
	}
	items, _, err := s.ReadSoftwareCatalog(ctx, Scope{TenantID: 1, SiteID: 1}, "", "Owned", "windows", "reader", permissions)
	if err != nil || len(items) != 3 {
		t.Fatal("shared catalog Windows filter", len(items), err)
	}
	if items, _, err = s.ReadSoftwareCatalog(ctx, scope, "", "%", "windows", "admin", permissions); err != nil || len(items) != 0 {
		t.Fatal("search wildcard expanded", err)
	}
	if items, _, err = s.ReadSoftwareCatalog(ctx, scope, "", "", "macos", "admin", permissions); err != nil || len(items) != 1 {
		t.Fatal("Mac catalog projection regressed", err)
	}
	versionID := items[0].ID
	if _, err = s.db.Exec(`CREATE FUNCTION reject_software_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('software.catalog.read','software.windows.version.publish') THEN RAISE EXCEPTION 'owned audit failure'; END IF; RETURN NEW; END $$;CREATE TRIGGER reject_software_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_software_audit()`); err != nil {
		t.Fatal(err)
	}
	if items, _, err = s.ReadSoftwareCatalog(ctx, scope, "", "", "", "admin", permissions); err == nil || items != nil {
		t.Fatal("data returned without read audit", err)
	}
	if version, err := s.ReadSoftwareVersion(ctx, scope, versionID, "admin", permissions); err == nil || version != nil {
		t.Fatal("version returned without read audit", err)
	}
	request := uuid.NewString()
	if _, err = s.PublishWindowsSoftware(ctx, scope, request, testWindowsSoftware("windows-msi"), "admin", permissions); err == nil {
		t.Fatal("publication survived audit failure")
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_software_versions WHERE approval_request_id=$1`, request).Scan(&count); err != nil || count != 0 {
		t.Fatal("unaudited approval persisted", count, err)
	}
}

func TestWindowsSoftwareCatalogPaginationAndRevokedAuthority(t *testing.T) {
	s, permissions := windowsSoftwareStore(t)
	ctx, scope := t.Context(), Scope{TenantID: 1}
	want := make(map[string]bool)
	input := testWindowsSoftware("windows-winget")
	input.Name = "Owned %_\\ package"
	request := ""
	for i := range 103 {
		input.Version = fmt.Sprintf("1.0.%d", i)
		request = uuid.NewString()
		v, err := s.PublishWindowsSoftware(ctx, scope, request, input, "second-admin", permissions)
		if err != nil {
			t.Fatal(err)
		}
		want[v.ID] = true
		if i%50 == 0 {
			mac := testMacAppPackage()
			mac.Name = input.Name
			if _, err := s.PublishMacAppPackage(ctx, scope, mac, "admin", permissions); err != nil {
				t.Fatal(err)
			}
		}
	}
	readScope := Scope{TenantID: 1, SiteID: 1}
	items, next, err := s.ReadSoftwareCatalog(ctx, readScope, "", "%_\\", "windows", "reader", permissions)
	if err != nil || len(items) != 100 || next != items[len(items)-1].ID {
		t.Fatal("filtered first page", len(items), next, err)
	}
	rest, end, err := s.ReadSoftwareCatalog(ctx, readScope, next, "%_\\", "windows", "reader", permissions)
	if err != nil || len(rest) != 3 || end != "" {
		t.Fatal("filtered last page", len(rest), end, err)
	}
	for _, v := range append(items, rest...) {
		if v.Platform != "windows" || !want[v.ID] {
			t.Fatal("foreign or repeated filtered result", v.ID)
		}
		delete(want, v.ID)
	}
	if len(want) != 0 {
		t.Fatal("filtered revisions skipped")
	}
	var reads int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE actor='reader' AND action='software.catalog.read' AND details->>'site_id'='1'`).Scan(&reads); err != nil || reads != 2 {
		t.Fatal("read audit lost site", reads, err)
	}
	foreign, err := s.PublishWindowsSoftware(ctx, Scope{TenantID: 2}, uuid.NewString(), input, "admin", permissions)
	if err != nil {
		t.Fatal(err)
	}
	if page, _, err := s.ReadSoftwareCatalog(ctx, readScope, foreign.ID, "", "windows", "reader", permissions); !errors.Is(err, ErrNotFound) || page != nil {
		t.Fatal("foreign cursor revealed timestamp", err)
	}
	for _, actor := range []string{"reader", "second-admin"} {
		principal, err := permissions.Principal(ctx, actor)
		if err != nil {
			t.Fatal(err)
		}
		if err := permissions.ReplaceGrants(ctx, "admin", actor, principal.Revision, nil); err != nil {
			t.Fatal(err)
		}
	}
	if page, _, err := s.ReadSoftwareCatalog(ctx, readScope, next, "", "windows", "reader", permissions); !errors.Is(err, access.ErrDenied) || page != nil {
		t.Fatal("revoked reader retained pagination", err)
	}
	if v, err := s.ReadSoftwareVersion(ctx, readScope, next, "reader", permissions); !errors.Is(err, access.ErrDenied) || v != nil {
		t.Fatal("revoked reader retained detail access", err)
	}
	if v, err := s.PublishWindowsSoftware(ctx, scope, request, input, "second-admin", permissions); !errors.Is(err, access.ErrDenied) || v != nil {
		t.Fatal("revoked publisher retained request replay", err)
	}
}
