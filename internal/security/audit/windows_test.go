package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// These deliberately small source schemas exercise the audit adapters without
// performing device enrollment. Console integration also checks the real Windows
// schema and immutable parents produced by synthetic protocol exchanges.
func windowsAuditTestStore(t *testing.T) *Store {
	t.Helper()
	s := testStore(t, false)
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()}
	for _, name := range []string{"mdm_windows_update_runs", "mdm_windows_unenrollment_requests", "mdm_windows_certificate_reminders"} {
		if _, err := s.db.Exec(`CREATE TABLE ` + name + `(id UUID PRIMARY KEY,tenant_id BIGINT NOT NULL,site_id BIGINT NOT NULL,encrypted_intent TEXT NOT NULL DEFAULT 'must-not-export-password')`); err != nil {
			t.Fatal(err)
		}
		for i, id := range ids {
			tenant, site := 1, 11
			if i == 1 {
				tenant, site = 2, 21
			}
			if i == 2 {
				site = 12
			}
			if _, err := s.db.Exec(`INSERT INTO `+name+`(id,tenant_id,site_id) VALUES($1,$2,$3)`, id, tenant, site); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, source := range windowsSources {
		if _, err := s.db.Exec(`CREATE TABLE ` + source.table + `(id BIGSERIAL PRIMARY KEY,tenant_id BIGINT NOT NULL,site_id BIGINT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,resource_id UUID,authority_id UUID,session_id UUID,command_id UUID,run_id UUID,ring_id UUID,rollout_id UUID,schedule_id UUID,renewal_id UUID,report_id UUID,request_id UUID,reminder_id UUID,delivery_id UUID,created_at TIMESTAMPTZ NOT NULL,payload TEXT NOT NULL DEFAULT 'must-not-export-password')`); err != nil {
			t.Fatal(err)
		}
		for i, id := range ids {
			tenant, site := 1, 11
			if i == 1 {
				tenant, site = 2, 21
			}
			if i == 2 {
				site = 12
			}
			age := 40
			if i == 3 {
				age = 1
			}
			if _, err := s.db.Exec(`INSERT INTO `+source.table+`(id,tenant_id,site_id,actor,action,resource_id,authority_id,session_id,command_id,run_id,ring_id,schedule_id,renewal_id,report_id,request_id,reminder_id,created_at) VALUES($1,$2,$3,'synthetic-windows-admin','synthetic.recorded',$4,$4,$4,$4,$4,$4,$4,$4,$4,$4,$4,date_trunc('day',clock_timestamp())-$5::integer*interval '1 day')`, i+1, tenant, site, id, age); err != nil {
				t.Fatal(err)
			}
		}
	}
	for range 2 {
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func windowsAuditFilter(scope access.Scope) Filter {
	return Filter{Scope: scope, From: time.Now().UTC().AddDate(0, 0, -50), Until: time.Now().UTC().AddDate(0, 0, -2)}
}

func TestWindowsAuditSourcesScopeMetadataAndExport(t *testing.T) {
	s := windowsAuditTestStore(t)
	for _, scope := range []access.Scope{{}, {TenantID: 1}, {TenantID: 1, SiteID: 11}, {TenantID: 1, SiteID: 12}, {TenantID: 2}} {
		for _, source := range windowsSources {
			f := windowsAuditFilter(scope)
			f.Source = source.name
			page, err := s.List(t.Context(), "admin", f, "")
			if err != nil {
				t.Fatal(source.name, err)
			}
			want := 1
			if scope.TenantID == 0 {
				want = 3
			}
			if scope.TenantID == 1 && scope.SiteID == 0 {
				want = 2
			}
			if source.name == "windows_authority" && scope.SiteID != 0 {
				want = 0
			}
			if len(page.Events) != want {
				t.Fatal("incorrect historical scope", source.name, scope, len(page.Events), want)
			}
			for _, event := range page.Events {
				if event.Source != source.name || event.Result != "recorded" || event.Resource == "" || scope.TenantID > 0 && event.TenantID != scope.TenantID || scope.SiteID > 0 && event.SiteID != scope.SiteID {
					t.Fatal("source metadata crossed scope")
				}
				if source.name == "windows_management" && event.Actor != "windows-device" {
					t.Fatal("management actor was invented from another field")
				}
			}
		}
	}
	f := windowsAuditFilter(access.Scope{TenantID: 1})
	for _, actor := range []string{"viewer", "operator"} {
		if page, err := s.List(t.Context(), actor, f, ""); !errors.Is(err, access.ErrDenied) || page != nil {
			t.Fatal("unprivileged Windows audit read", actor, err)
		}
	}
	foreign := f
	foreign.Scope.TenantID = 2
	if page, err := s.List(t.Context(), "organization-admin", foreign, ""); !errors.Is(err, access.ErrDenied) || page != nil {
		t.Fatal("cross-organization audit read", err)
	}
	for _, export := range []func(context.Context, string, Filter) ([]byte, error){s.ExportCSV, s.ExportJSON} {
		data, err := export(t.Context(), "organization-admin", f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "must-not-export-password") {
			t.Fatal("audit export copied protected source columns")
		}
		for _, source := range windowsSources {
			if !strings.Contains(string(data), source.name) {
				t.Fatal("export omitted Windows source", source.name)
			}
		}
	}
	f.Result = "success"
	if page, err := s.List(t.Context(), "organization-admin", f, ""); err != nil || len(page.Events) != 0 {
		t.Fatal("recorded actions became compliance claims", err)
	}
	if _, err := s.db.Exec(`CREATE FUNCTION fail_windows_audit_activity() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic private audit failure'; END $$; CREATE TRIGGER fail_windows_audit_activity BEFORE INSERT ON uem_audit_activity FOR EACH ROW EXECUTE FUNCTION fail_windows_audit_activity()`); err != nil {
		t.Fatal(err)
	}
	f.Result = ""
	if page, err := s.List(t.Context(), "organization-admin", f, ""); err == nil || page != nil {
		t.Fatal("unaudited Windows timeline escaped")
	}
	if data, err := s.ExportJSON(t.Context(), "organization-admin", f); err == nil || data != nil {
		t.Fatal("unaudited Windows export escaped")
	}
}

func TestWindowsAuditCursorSeparatesEqualSourceEventIDs(t *testing.T) {
	s := windowsAuditTestStore(t)
	for _, source := range windowsSources {
		if _, err := s.db.Exec(`INSERT INTO ` + source.table + ` SELECT n,a.tenant_id,a.site_id,a.actor,a.action,a.resource_id,a.authority_id,a.session_id,a.command_id,a.run_id,a.ring_id,a.rollout_id,a.schedule_id,a.renewal_id,a.report_id,a.request_id,a.reminder_id,a.delivery_id,a.created_at,a.payload FROM ` + source.table + ` a CROSS JOIN generate_series(5,15) n WHERE a.id=1`); err != nil {
			t.Fatal(err)
		}
	}
	f := windowsAuditFilter(access.Scope{TenantID: 1})
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		page, err := s.List(t.Context(), "organization-admin", f, cursor)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if len(page.Events) > 100 {
			t.Fatal("unbounded audit page")
		}
		for _, event := range page.Events {
			key := fmt.Sprintf("%s/%d", event.Source, event.ID)
			if seen[key] {
				t.Fatal("source cursor repeated an event")
			}
			seen[key] = true
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
		if pages > 3 {
			t.Fatal("cursor failed to terminate")
		}
	}
	if len(seen) != 13*len(windowsSources) || pages != 2 {
		t.Fatal("equal timestamp/source IDs lost events", len(seen), pages)
	}
}

func windowsAuditSetRetention(t *testing.T, s *Store, days int, enabled bool) {
	t.Helper()
	preview, err := s.PreviewRetentionWithWindows(t.Context(), "organization-admin", access.Scope{TenantID: 1}, days, enabled)
	if err != nil {
		t.Fatal(err)
	}
	if preview.WindowsEnabled != enabled {
		t.Fatal("preview changed Windows selection")
	}
	for _, source := range windowsSources {
		_, present := preview.Counts[source.name]
		if present != enabled {
			t.Fatal("preview omitted or silently included Windows", source.name)
		}
	}
	if err := s.ApplyRetention(t.Context(), "organization-admin", access.Scope{TenantID: 1}, preview.ID, preview.Token); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyRetention(t.Context(), "organization-admin", access.Scope{TenantID: 1}, preview.ID, preview.Token); !errors.Is(err, ErrConflict) {
		t.Fatal("retention preview replay accepted", err)
	}
}

func TestWindowsAuditRetentionRequiresExplicitInclusionAndReceipts(t *testing.T) {
	s := windowsAuditTestStore(t)
	windowsAuditSetRetention(t, s, 30, false)
	if err := s.PruneRetention(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, source := range windowsSources {
		var count int
		if err := s.db.QueryRow(`SELECT count(*) FROM ` + source.table).Scan(&count); err != nil || count != 4 {
			t.Fatal("legacy retention acquired Windows rows", source.name, count, err)
		}
	}
	for _, statement := range []string{`DELETE FROM mdm_windows_csp_audit WHERE id=1`, `UPDATE mdm_windows_csp_audit SET actor='changed' WHERE id=1`, `DELETE FROM mdm_windows_audit WHERE id=1`, `UPDATE mdm_windows_authority_audit SET action='changed' WHERE id=1`} {
		if _, err := s.db.Exec(statement); err == nil {
			t.Fatal("unreceipted history mutation accepted")
		}
	}
	windowsAuditSetRetention(t, s, 30, true)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- s.PruneRetention(t.Context()) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, source := range windowsSources {
		var count int
		if err := s.db.QueryRow(`SELECT count(*) FROM ` + source.table + ` WHERE id IN (2,4)`).Scan(&count); err != nil || count != 2 {
			t.Fatal("foreign or recent audit evidence removed", source.name, err)
		}
		if err := s.db.QueryRow(`SELECT count(*) FROM ` + source.table).Scan(&count); err != nil || count != 2 {
			t.Fatal("eligible audit evidence not pruned", source.name, count, err)
		}
	}
	var count, total int
	if err := s.db.QueryRow(`SELECT count(*),sum(jsonb_array_length(event_ids)) FROM uem_audit_windows_batches`).Scan(&count, &total); err != nil || count != len(windowsSources) || total != 2*len(windowsSources) {
		t.Fatal("deletion receipts missing or duplicated", count, total, err)
	}
	policy, history, err := s.Retention(t.Context(), "organization-admin", access.Scope{TenantID: 1})
	if err != nil || !policy.WindowsEnabled {
		t.Fatal("stored inclusion lost", err)
	}
	for _, event := range history {
		if event.Action == "retention.prune" && (!event.WindowsEnabled || event.Count != 2 || !isWindowsSource(event.Source)) {
			t.Fatal("receipt lost source/policy")
		}
	}
	for _, statement := range []string{`DELETE FROM uem_audit_windows_batches`, `UPDATE uem_audit_windows_batches SET policy_revision=policy_revision+1`, `UPDATE uem_audit_retention_history SET event_count=0 WHERE id IN (SELECT receipt_id FROM uem_audit_windows_batches)`, `DELETE FROM uem_audit_retention_history WHERE id IN (SELECT receipt_id FROM uem_audit_windows_batches)`} {
		if _, err := s.db.Exec(statement); err == nil {
			t.Fatal("committed Windows receipt changed")
		}
	}
	// Reintroducing an ID in the synthetic source cannot reuse an earlier
	// transaction's immutable deletion authorization.
	if _, err := s.db.Exec(`INSERT INTO mdm_windows_csp_audit SELECT 1,tenant_id,site_id,actor,action,resource_id,authority_id,session_id,command_id,run_id,ring_id,rollout_id,schedule_id,renewal_id,report_id,request_id,reminder_id,delivery_id,clock_timestamp()-interval '40 days',payload FROM mdm_windows_csp_audit WHERE id=4`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM mdm_windows_csp_audit WHERE id=1`); err == nil {
		t.Fatal("committed batch reused for another deletion")
	}
	windowsAuditSetRetention(t, s, 30, false)
	if err := s.PruneRetention(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_windows_csp_audit WHERE id=1`).Scan(&count); err != nil || count != 1 {
		t.Fatal("disabled Windows cleanup continued", err)
	}
	for _, scope := range []access.Scope{{}, {TenantID: 1, SiteID: 11}} {
		if p, err := s.PreviewRetentionWithWindows(t.Context(), "admin", scope, 30, true); !errors.Is(err, ErrInvalid) || p != nil {
			t.Fatal("invalid Windows retention scope")
		}
	}
}

func TestWindowsAuditRetentionFailureRollsBackEverySource(t *testing.T) {
	s := windowsAuditTestStore(t)
	windowsAuditSetRetention(t, s, 30, true)
	if _, err := s.db.Exec(`CREATE FUNCTION fail_windows_retention_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.source='windows_csp' THEN RAISE EXCEPTION 'synthetic receipt failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_windows_retention_receipt BEFORE INSERT ON uem_audit_retention_history FOR EACH ROW EXECUTE FUNCTION fail_windows_retention_receipt()`); err != nil {
		t.Fatal(err)
	}
	if err := s.PruneRetention(t.Context()); err == nil {
		t.Fatal("failed receipt admitted deletion")
	}
	for _, source := range windowsSources {
		var count int
		if err := s.db.QueryRow(`SELECT count(*) FROM ` + source.table).Scan(&count); err != nil || count != 4 {
			t.Fatal("failed later source retained earlier deletion", source.name, err)
		}
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM uem_audit_windows_batches`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed sweep retained a receipt", err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_windows_retention_receipt ON uem_audit_retention_history; ALTER TABLE mdm_windows_csp_audit DISABLE TRIGGER uem_audit_windows_history`); err != nil {
		t.Fatal(err)
	}
	if err := s.PruneRetention(t.Context()); err == nil {
		t.Fatal("unprotected source pruned")
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal("source guard could not be restored", err)
	}
	if err := s.PruneRetention(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsAuditGuardRejectsMismatchedDeletionAuthority(t *testing.T) {
	s := windowsAuditTestStore(t)
	windowsAuditSetRetention(t, s, 30, true)
	for _, name := range []string{"tenant", "source", "revision", "ids", "age", "count", "table", "disabled"} {
		t.Run(name, func(t *testing.T) {
			tx, err := s.db.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			p, err := retentionPolicy(t.Context(), tx, 1, true)
			if err != nil {
				t.Fatal(err)
			}
			tenant, revision, source, table, ids, count := 1, p.Revision, "windows_csp", "mdm_windows_csp_audit", []int64{1}, 1
			cutoff := time.Now().UTC().AddDate(0, 0, -30)
			switch name {
			case "tenant":
				tenant = 2
			case "source":
				source = "windows_enrollment"
			case "revision":
				revision++
			case "ids":
				ids = []int64{3}
			case "age":
				cutoff = time.Now().Add(time.Hour)
			case "count":
				count = 2
			case "table":
				table = "mdm_windows_audit"
			case "disabled":
				if _, err := tx.Exec(`UPDATE uem_audit_retention SET windows_enabled=false WHERE tenant_id=1`); err != nil {
					t.Fatal(err)
				}
			}
			var receipt int64
			if err := tx.QueryRow(`INSERT INTO uem_audit_retention_history(tenant_id,actor,action,days,revision,source,cutoff,event_count,windows_enabled) VALUES($1,'retention-service','retention.prune',30,$2,$3,$4,$5,true) RETURNING id`, tenant, revision, source, cutoff, count).Scan(&receipt); err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(ids)
			if _, err := tx.Exec(`INSERT INTO uem_audit_windows_batches(receipt_id,table_oid,source,tenant_id,policy_revision,cutoff,event_ids) VALUES($1,$2::regclass::oid,$3,$4,$5,$6,$7::jsonb)`, receipt, table, source, tenant, revision, cutoff, string(encoded)); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(`DELETE FROM mdm_windows_csp_audit WHERE id=1`); err == nil {
				t.Fatal("mismatched deletion authority accepted", name)
			}
		})
	}
}

func TestWindowsAuditRetentionBoundsAndReschedulesBatches(t *testing.T) {
	s := windowsAuditTestStore(t)
	if _, err := s.db.Exec(`INSERT INTO mdm_windows_csp_audit(id,tenant_id,site_id,actor,action,command_id,created_at) SELECT n,1,11,'synthetic-admin','synthetic.recorded',command_id,created_at FROM mdm_windows_csp_audit CROSS JOIN generate_series(5,1104) n WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	windowsAuditSetRetention(t, s, 30, true)
	check := func(wantRemaining, wantBatches, wantTotal int, wantSoon bool) {
		t.Helper()
		var remaining, batches, total int
		var soon bool
		if err := s.db.QueryRow(`SELECT count(*) FROM mdm_windows_csp_audit WHERE tenant_id=1 AND created_at<clock_timestamp()-interval '30 days'`).Scan(&remaining); err != nil {
			t.Fatal(err)
		}
		if err := s.db.QueryRow(`SELECT count(*),COALESCE(sum(jsonb_array_length(event_ids)),0) FROM uem_audit_windows_batches WHERE source='windows_csp'`).Scan(&batches, &total); err != nil {
			t.Fatal(err)
		}
		if err := s.db.QueryRow(`SELECT next_sweep_at BETWEEN clock_timestamp() AND clock_timestamp()+interval '2 minutes' FROM uem_audit_retention WHERE tenant_id=1`).Scan(&soon); err != nil {
			t.Fatal(err)
		}
		if remaining != wantRemaining || batches != wantBatches || total != wantTotal || soon != wantSoon {
			t.Fatal("unbounded or incorrectly rescheduled cleanup", remaining, batches, total, soon)
		}
	}
	if err := s.PruneRetention(t.Context()); err != nil {
		t.Fatal(err)
	}
	check(102, 1, 1000, true)
	// An immediate sweep must respect the scheduled retry, even with work left.
	if err := s.PruneRetention(t.Context()); err != nil {
		t.Fatal(err)
	}
	check(102, 1, 1000, true)
	if _, err := s.db.Exec(`UPDATE uem_audit_retention SET next_sweep_at=clock_timestamp() WHERE tenant_id=1`); err != nil {
		t.Fatal(err)
	}
	if err := s.PruneRetention(t.Context()); err != nil {
		t.Fatal(err)
	}
	check(0, 2, 1102, false)
	var surviving int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_windows_csp_audit WHERE id IN (2,4)`).Scan(&surviving); err != nil || surviving != 2 {
		t.Fatal("batched deletion lost foreign or recent events", err)
	}
}

func TestWindowsAuditUpgradePreservesLegacyPolicyAndPreviewScope(t *testing.T) {
	s := testStoreWithAuditMigration(t, false, false)
	baseline, err := migrations.ReadFile("migrations/001_audit.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(string(baseline)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`CREATE TABLE uem_audit_migrations(name TEXT PRIMARY KEY,applied_at TIMESTAMPTZ NOT NULL DEFAULT now()); INSERT INTO uem_audit_migrations(name) VALUES('migrations/001_audit.sql'); INSERT INTO uem_audit_retention(tenant_id,days,revision,updated_by) VALUES(1,30,7,'organization-admin'); INSERT INTO uem_audit_retention_history(tenant_id,actor,action,days,revision) VALUES(1,'organization-admin','retention.change',30,7); CREATE TABLE mdm_windows_audit(id BIGSERIAL PRIMARY KEY,tenant_id BIGINT NOT NULL,site_id BIGINT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,resource_id UUID NOT NULL,created_at TIMESTAMPTZ NOT NULL); INSERT INTO mdm_windows_audit(tenant_id,site_id,actor,action,resource_id,created_at) VALUES(1,11,'synthetic-admin','synthetic.recorded','00000000-0000-0000-0000-000000000001',clock_timestamp()-interval '100 days')`); err != nil {
		t.Fatal(err)
	}
	id, token := uuid.NewString(), strings.Repeat("p", 43)
	if _, err = s.db.Exec(`INSERT INTO uem_audit_retention_previews(id,token_hash,actor,tenant_id,days,revision,counts) VALUES($1,$2,'organization-admin',1,60,7,'{}')`, id, previewTokenHash(token)); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	p, history, err := s.Retention(t.Context(), "organization-admin", access.Scope{TenantID: 1})
	if err != nil || p.Days != 30 || p.Revision != 7 || p.WindowsEnabled || len(history) != 1 || history[0].WindowsEnabled || history[0].PreviousWindowsEnabled != nil {
		t.Fatal("upgrade changed legacy policy/history", p, err)
	}
	if err = s.ApplyRetention(t.Context(), "organization-admin", access.Scope{TenantID: 1}, id, token); err != nil {
		t.Fatal("upgrade invalidated a legacy review", err)
	}
	p, _, err = s.Retention(t.Context(), "organization-admin", access.Scope{TenantID: 1})
	if err != nil || p.Days != 60 || p.Revision != 8 || p.WindowsEnabled {
		t.Fatal("legacy preview acquired Windows deletion", p, err)
	}
	if err = s.PruneRetention(t.Context()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_windows_audit`).Scan(&count); err != nil || count != 1 {
		t.Fatal("upgrade erased Windows evidence", err)
	}
	if _, err = s.db.Exec(`DELETE FROM mdm_windows_audit`); err == nil {
		t.Fatal("upgrade left Windows audit unguarded")
	}
}
