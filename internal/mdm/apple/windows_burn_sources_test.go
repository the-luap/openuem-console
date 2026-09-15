package apple

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-console/internal/software/winget"
)

func TestWindowsBurnDefinitionRejectsChangedBundleAndExecutionRules(t *testing.T) {
	for index, change := range []func(*WindowsSoftwareInput){
		func(p *WindowsSoftwareInput) { p.Execution.UninstallURL = "https://example.invalid/other.exe" },
		func(p *WindowsSoftwareInput) { p.Execution.UninstallSHA256 = strings.Repeat("b", 64) },
		func(p *WindowsSoftwareInput) { p.Execution.InstallArguments = []string{"/quiet"} },
		func(p *WindowsSoftwareInput) { p.Execution.UninstallArguments = []string{"/quiet", "/norestart"} },
		func(p *WindowsSoftwareInput) { p.Execution.MSIProperties = map[string]string{"PROPERTY": "value"} },
		func(p *WindowsSoftwareInput) { p.Detection.UninstallKey = strings.ToLower(p.Detection.UninstallKey) },
		func(p *WindowsSoftwareInput) { p.Detection.UninstallKey = "{00000000-0000-0000-0000-000000000000}" },
		func(p *WindowsSoftwareInput) { p.Detection.RegistryView = "32" },
		func(p *WindowsSoftwareInput) { p.Detection = testWindowsSoftware("windows-msi").Detection },
		func(p *WindowsSoftwareInput) { p.Architecture = "x86" },
		func(p *WindowsSoftwareInput) { p.SuccessCodes = []uint32{0, 1641} },
		func(p *WindowsSoftwareInput) { p.RebootCodes = nil },
	} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			input := testWindowsSoftware("windows-burn")
			change(&input)
			if input.Validate() == nil {
				t.Fatal("changed Burn behavior accepted as an approval")
			}
			wire, _ := input.canonical()
			defer clear(wire)
			for _, operation := range []string{"install", "remove"} {
				if _, err := windowsExecutablePlan(wire, operation); err == nil {
					t.Fatal("changed Burn behavior entered an executable plan")
				}
			}
		})
	}
}

func windowsBurnSourceFixture(t *testing.T, operation string) (*windowsDispatchFixture, WindowsSoftwareInput, winget.Snapshot, string) {
	t.Helper()
	f := newWindowsDispatchFixture(t, "windows-msi", operation)
	ctx, scope := t.Context(), Scope{TenantID: 1}
	if err := f.store.CancelWindowsSoftwarePreparation(ctx, Scope{TenantID: 1, SiteID: 1}, f.version.ID, f.request.ID, "operator", f.permissions); err != nil {
		t.Fatal(err)
	}
	input := testWindowsSoftware("windows-winget")
	input.Identifier = "Vendor.Burn"
	snapshot := windowsSourceSnapshot(t, input)
	input.Detection = WindowsSoftwareDetection{Kind: "uninstall-key", UninstallKey: input.Detection.ProductCode, RegistryView: "64", Version: input.Detection.Version}
	snapshot.Content = []byte(strings.ReplaceAll(strings.ReplaceAll(string(snapshot.Content), "InstallerType: wix", "InstallerType: burn"), ".msi", ".exe"))
	digest := sha256.Sum256(snapshot.Content)
	snapshot.SHA256 = hex.EncodeToString(digest[:])
	original, err := f.store.PublishWindowsSoftware(ctx, scope, uuid.NewString(), input, "admin", f.permissions)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	if _, err = f.store.ResolveWindowsSoftwareSource(ctx, scope, original.ID, id, "admin", f.permissions, fixedWindowsSource(snapshot)); err != nil {
		t.Fatal(err)
	}
	review, err := f.store.ReviewWindowsSoftwareSource(ctx, scope, original.ID, id, "admin", f.permissions)
	if err != nil || len(review.Options) != 1 || review.Options[0].Kind != "windows-burn" || review.Options[0].Index != 0 {
		t.Fatal("exact Burn option unavailable", err)
	}
	public, _ := json.Marshal(review)
	if bytes.Contains(public, []byte("source-secret")) || bytes.Contains(public, []byte("private-download")) {
		t.Fatal("Burn review exposed the private artifact URL")
	}
	f.version, err = f.store.ApproveWindowsSoftwareSource(ctx, scope, original.ID, id, uuid.NewString(), 0, review.Options[0].ReviewHash, "admin", f.permissions)
	if err != nil || f.version.Kind != "windows-burn" {
		t.Fatal("Burn approval lost its explicit kind", err)
	}
	f.request, err = f.store.PrepareWindowsSoftware(ctx, Scope{TenantID: 1, SiteID: 1}, uuid.NewString(), f.version.ID, f.identity.DeviceID, operation, "operator", f.permissions)
	if err != nil {
		t.Fatal(err)
	}
	f.assertNoDispatch(t)
	return f, input, snapshot, id
}

func registerBurnVersion(t *testing.T, f *windowsDispatchFixture, version int) {
	t.Helper()
	reply, err := f.call(t, enrollment.SoftwareRequest{Action: "challenge", PublicKey: f.key.PublicKey(), BurnVersion: version})
	if err != nil || reply.Registration == nil || reply.Registration.BurnVersion != version {
		t.Fatal("Burn challenge unavailable", err)
	}
	signature, err := enrollment.SignSoftwareRegistration(*reply.Registration, f.cert, f.keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	reply, err = f.call(t, enrollment.SoftwareRequest{Action: "register", Registration: reply.Registration, Signature: signature})
	if err != nil || reply.Recipient == nil || reply.Recipient.BurnVersion != version {
		t.Fatal("device-signed Burn registration unavailable", err)
	}
	f.recipient = reply.Recipient
}

func TestWindowsBurnSourceDispatchRequiresSignedCapabilityAndExactProvenance(t *testing.T) {
	for _, operation := range []string{"install", "remove"} {
		t.Run(operation, func(t *testing.T) {
			f, input, snapshot, sourceID := windowsBurnSourceFixture(t, operation)
			ctx, scope := t.Context(), Scope{TenantID: 1, SiteID: 1}
			if _, err := f.store.db.Exec(`UPDATE uem_software_versions SET withdrawn_at=clock_timestamp() WHERE id=(SELECT source_version_id FROM uem_windows_software_sources WHERE id=$1)`, sourceID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.ReviewWindowsSoftwareDispatch(ctx, scope, f.version.ID, f.request.ID, "operator", f.permissions); err == nil {
				t.Fatal("legacy recipient could review Burn dispatch")
			}
			f.assertNoDispatch(t)
			registerBurnVersion(t, f, 1)
			review := f.review(t)
			registerBurnVersion(t, f, 0)
			if _, err := f.store.DispatchWindowsSoftware(ctx, scope, f.version.ID, f.request.ID, uuid.NewString(), review.ReviewHash, "operator", f.permissions); err == nil {
				t.Fatal("withdrawn Burn capability retained dispatch authority")
			}
			f.assertNoDispatch(t)
			registerBurnVersion(t, f, 1)
			if _, err := f.store.DispatchWindowsSoftware(ctx, scope, f.version.ID, f.request.ID, uuid.NewString(), review.ReviewHash, "operator", f.permissions); err == nil {
				t.Fatal("obsolete review survived recipient replacement")
			}
			f.assertNoDispatch(t)
			review = f.review(t)
			if _, err := f.store.DispatchWindowsSoftware(ctx, scope, f.version.ID, f.request.ID, uuid.NewString(), review.ReviewHash, "operator", f.permissions); err != nil {
				t.Fatal(err)
			}
			reply, err := f.call(t, enrollment.SoftwareRequest{Action: "poll", RecipientID: f.recipient.ID})
			if err != nil || reply.Task == nil {
				t.Fatal("approved Burn task unavailable", err)
			}
			secret, err := f.key.Open(*reply.Task, f.authority, f.recipient.Identity, f.recipient.ID, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Close()
			expected, err := winget.BurnPlan(snapshot, 0, winget.BurnTarget(sourceMSITarget(input)), operation)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := expected.Digest()
			got, _ := secret.Plan.Digest()
			if want != got || reply.Task.Context.RevisionID != f.version.ID || reply.Task.Context.PreparationID != f.request.ID {
				t.Fatal("encrypted Burn dispatch changed immutable source intent")
			}
			detail, err := f.store.ReadSoftwareVersion(ctx, scope, f.version.ID, "reader", f.permissions)
			if err != nil || detail.WinGetSource == nil || detail.WinGetSource.ID != sourceID || detail.WinGetSource.Approval.VersionID != f.version.ID {
				t.Fatal("Burn revision lost verified source history", err)
			}
		})
	}
}

func TestWindowsBurnDispatchRequiresSourceApproval(t *testing.T) {
	f := newWindowsDispatchFixture(t, "windows-burn", "install")
	registerBurnVersion(t, f, 1)
	if _, err := f.store.ReviewWindowsSoftwareDispatch(t.Context(), Scope{TenantID: 1, SiteID: 1}, f.version.ID, f.request.ID, "operator", f.permissions); err == nil {
		t.Fatal("Burn revision without source provenance was dispatchable")
	}
	f.assertNoDispatch(t)
}

func TestWindowsBurnSourceCorruptionCannotAuthorizeDispatch(t *testing.T) {
	f, _, _, sourceID := windowsBurnSourceFixture(t, "install")
	registerBurnVersion(t, f, 1)
	review := f.review(t)
	alterSourceEnvelope(t, f.store, sourceID, func(envelope *windowsSourceEnvelope) { envelope.Snapshot.Commit = strings.Repeat("b", 40) })
	if _, err := f.store.DispatchWindowsSoftware(t.Context(), Scope{TenantID: 1, SiteID: 1}, f.version.ID, f.request.ID, uuid.NewString(), review.ReviewHash, "operator", f.permissions); err == nil {
		t.Fatal("changed source provenance authorized Burn dispatch")
	}
	f.assertNoDispatch(t)
	if _, err := f.store.ReadSoftwareVersion(t.Context(), Scope{TenantID: 1, SiteID: 1}, f.version.ID, "reader", f.permissions); err == nil {
		t.Fatal("changed Burn history appeared verified")
	}
}

func TestWindowsBurnMigrationPreservesExistingApprovalEvidence(t *testing.T) {
	s, p, v, identity, _ := windowsRequestFixtureBeforeMigration(t, "migrations/042_windows_burn_sources.sql")
	input, scope := testWindowsSoftware("windows-winget"), Scope{TenantID: 1}
	original, err := s.PublishWindowsSoftware(t.Context(), scope, uuid.NewString(), input, "admin", p)
	if err != nil {
		t.Fatal(err)
	}
	sourceID := uuid.NewString()
	if _, err = s.ResolveWindowsSoftwareSource(t.Context(), scope, original.ID, sourceID, "admin", p, fixedWindowsSource(windowsSourceSnapshot(t, input))); err != nil {
		t.Fatal(err)
	}
	review, err := s.ReviewWindowsSoftwareSource(t.Context(), scope, original.ID, sourceID, "admin", p)
	if err != nil || len(review.Options) != 1 {
		t.Fatal("pre-migration MSI source review unavailable", err)
	}
	derived, err := s.ApproveWindowsSoftwareSource(t.Context(), scope, original.ID, sourceID, uuid.NewString(), 0, review.Options[0].ReviewHash, "admin", p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareWindowsSoftware(t.Context(), Scope{TenantID: 1, SiteID: 1}, uuid.NewString(), v.ID, identity.DeviceID, "install", "operator", p); err != nil {
		t.Fatal(err)
	}
	snapshot := func() []byte {
		t.Helper()
		var data []byte
		if err := s.db.QueryRow(`SELECT json_build_object('versions',(SELECT json_agg(row_to_json(v) ORDER BY v.id) FROM uem_software_versions v),'requests',(SELECT json_agg(row_to_json(r) ORDER BY r.id) FROM uem_windows_software_requests r),'sources',(SELECT json_agg(row_to_json(s) ORDER BY s.id) FROM uem_windows_software_sources s),'approvals',(SELECT json_agg(row_to_json(a) ORDER BY a.id) FROM uem_windows_software_source_approvals a))`).Scan(&data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	before := snapshot()
	for range 2 {
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(before, snapshot()) {
		t.Fatal("Burn migration rewrote an existing revision or preparation")
	}
	detail, err := s.ReadSoftwareVersion(t.Context(), Scope{TenantID: 1, SiteID: 1}, derived.ID, "reader", p)
	if err != nil || detail.Kind != "windows-msi" || detail.WinGetSource == nil || detail.WinGetSource.ID != sourceID {
		t.Fatal("Burn migration changed existing MSI source evidence", err)
	}
}
