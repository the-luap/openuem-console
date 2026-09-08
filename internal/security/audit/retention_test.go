package audit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestRetentionGlobalPolicyIsIndependentAndCanBeDisabled(t *testing.T) {
	s := testStore(t, true)
	if _, err := s.db.Exec(`UPDATE uem_access_audit SET created_at=clock_timestamp()-interval '100 days'; INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,created_at) VALUES(1,'fixture','old','device',clock_timestamp()-interval '100 days'); INSERT INTO uem_audit_activity(tenant_id,actor,action,resource_id,result,event_count,created_at) VALUES(0,'admin','audit.view',repeat('a',64),'success',0,clock_timestamp()-interval '100 days'),(1,'admin','audit.view',repeat('a',64),'success',0,clock_timestamp()-interval '100 days')`); err != nil {
		t.Fatal(err)
	}
	global := access.Scope{}
	preview, err := s.PreviewRetention(t.Context(), "admin", global, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Counts) != 3 || preview.Counts["access"] == 0 || preview.Counts["activity"] != 1 {
		t.Fatal("global preview included organization events", preview.Counts)
	}
	if err = s.ApplyRetention(t.Context(), "admin", global, preview.ID, preview.Token); err != nil {
		t.Fatal(err)
	}
	if err = s.PruneRetention(t.Context()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_access_audit`).Scan(&count); err != nil || count != 0 {
		t.Fatal("global policy did not erase global events", count, err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit`).Scan(&count); err != nil || count != 1 {
		t.Fatal("global policy erased organization events", count, err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_audit_activity WHERE tenant_id=1`).Scan(&count); err != nil || count != 1 {
		t.Fatal("global policy erased organization access", count, err)
	}
	preview, err = s.PreviewRetention(t.Context(), "admin", global, 0)
	if err != nil || preview.Cutoff != nil {
		t.Fatal("disable preview failed", err)
	}
	if err = s.ApplyRetention(t.Context(), "admin", global, preview.ID, preview.Token); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO uem_audit_activity(tenant_id,actor,action,resource_id,result,event_count,created_at) VALUES(0,'admin','audit.view',repeat('a',64),'success',0,clock_timestamp()-interval '100 days')`); err != nil {
		t.Fatal(err)
	}
	if err = s.PruneRetention(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_audit_activity WHERE tenant_id=0`).Scan(&count); err != nil || count != 1 {
		t.Fatal("disabled policy still erased events", count, err)
	}
}

func TestRetentionLatestPreviewRevocationAndPolicyAuditAtomicity(t *testing.T) {
	s := testStore(t, false)
	scope := access.Scope{TenantID: 1}
	for _, days := range []int{-1, 1, 29, 3651} {
		if _, err := s.PreviewRetention(t.Context(), "admin", scope, days); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid days accepted", days, err)
		}
	}
	if _, err := s.PreviewRetention(t.Context(), "admin", access.Scope{TenantID: 1, SiteID: 11}, 30); !errors.Is(err, ErrInvalid) {
		t.Fatal("site retention accepted", err)
	}
	first, err := s.PreviewRetention(t.Context(), "organization-admin", scope, 30)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.PreviewRetention(t.Context(), "organization-admin", scope, 90)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyRetention(t.Context(), "organization-admin", scope, first.ID, first.Token); !errors.Is(err, ErrConflict) {
		t.Fatal("superseded preview applied", err)
	}
	if _, err = s.db.Exec(`CREATE FUNCTION reject_policy() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test failure'; END $$; CREATE TRIGGER reject_policy BEFORE INSERT ON uem_audit_retention_history FOR EACH ROW EXECUTE FUNCTION reject_policy()`); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyRetention(t.Context(), "organization-admin", scope, second.ID, second.Token); err == nil {
		t.Fatal("policy saved without evidence")
	}
	policy, _, err := s.Retention(t.Context(), "organization-admin", scope)
	if err != nil || policy.Revision != 0 {
		t.Fatal("failed policy partially saved", policy, err)
	}
	if _, err = s.db.Exec(`DROP TRIGGER reject_policy ON uem_audit_retention_history`); err != nil {
		t.Fatal(err)
	}
	if err = s.permissions.ReplaceGrants(t.Context(), "admin", "organization-admin", 1, nil); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyRetention(t.Context(), "organization-admin", scope, second.ID, second.Token); !errors.Is(err, access.ErrDenied) {
		t.Fatal("revoked actor applied preview", err)
	}
}

func TestRetentionWorkerCancelsDatabaseWaitAndJoins(t *testing.T) {
	s := testStore(t, false)
	lock, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err = lock.Exec(`LOCK TABLE uem_audit_retention_previews IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); s.RunRetention(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err = s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation='uem_audit_retention_previews'::regclass AND NOT granted)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not begin its immediate sweep")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("retention worker did not join after cancellation")
	}
}

func TestRetentionNeedsBoundedScopedPreviewAndPreservesEvidence(t *testing.T) {
	s := testStore(t, true)
	scope := access.Scope{TenantID: 1}
	if _, err := s.db.Exec(`INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,created_at) SELECT 1,'fixture','old','device',clock_timestamp()-interval '100 days' FROM generate_series(1,1500); INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,created_at) VALUES(2,'fixture','foreign','device',clock_timestamp()-interval '100 days'),(1,'fixture','recent','device',clock_timestamp()); INSERT INTO uem_agent_audit(tenant_id,site_id,actor,action,resource_id,created_at) VALUES(1,11,'fixture','old','10000000-0000-0000-0000-000000000001',clock_timestamp()-interval '100 days')`); err != nil {
		t.Fatal(err)
	}
	if err := s.PruneRetention(t.Context()); err != nil {
		t.Fatal(err)
	}
	count := func(action string) int {
		t.Helper()
		var n int
		if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE action=$1`, action).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count("old") != 1500 {
		t.Fatal("default retention deleted historical events")
	}
	for _, actor := range []string{"operator", "viewer"} {
		if _, err := s.PreviewRetention(t.Context(), actor, scope, 30); !errors.Is(err, access.ErrDenied) {
			t.Fatal("reader can erase audit", actor, err)
		}
	}
	if _, err := s.PreviewRetention(t.Context(), "organization-admin", access.Scope{TenantID: 2}, 30); !errors.Is(err, access.ErrDenied) {
		t.Fatal("cross-tenant retention", err)
	}
	if _, err := s.PreviewRetention(t.Context(), "organization-admin", access.Scope{}, 30); !errors.Is(err, access.ErrDenied) {
		t.Fatal("global retention exposed", err)
	}
	preview, err := s.PreviewRetention(t.Context(), "organization-admin", scope, 30)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Policy.Days != 0 || preview.Policy.Revision != 0 || preview.Counts["apple"] != 1500 || preview.Counts["agent"] != 1 || preview.Cutoff == nil {
		t.Fatal("preview did not describe erasure", preview)
	}
	if err = s.ApplyRetention(t.Context(), "admin", scope, preview.ID, preview.Token); !errors.Is(err, ErrConflict) {
		t.Fatal("another account consumed a preview", err)
	}
	if err = s.ApplyRetention(t.Context(), "organization-admin", scope, preview.ID, strings.Repeat("a", 43)); !errors.Is(err, ErrConflict) {
		t.Fatal("confirmation token bypassed", err)
	}
	if err = s.ApplyRetention(t.Context(), "organization-admin", scope, preview.ID, preview.Token); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyRetention(t.Context(), "organization-admin", scope, preview.ID, preview.Token); !errors.Is(err, ErrConflict) {
		t.Fatal("confirmation reused", err)
	}
	var wg sync.WaitGroup
	failures := make([]error, 4)
	for i := range failures {
		wg.Go(func() { failures[i] = s.PruneRetention(t.Context()) })
	}
	wg.Wait()
	for _, err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if count("old") != 500 || count("foreign") != 1 || count("recent") != 1 {
		t.Fatal("erasure exceeded its batch or scope")
	}
	p, history, err := s.Retention(t.Context(), "organization-admin", scope)
	if err != nil || p.Days != 30 || p.Revision != 1 || len(history) != 3 {
		t.Fatal("policy and erasure evidence missing", p, history, err)
	}
	var retained int
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_access_audit`).Scan(&retained); err != nil || retained == 0 {
		t.Fatal("organization erasure deleted global access evidence", err)
	}
	if _, err = s.db.Exec(`UPDATE uem_audit_retention SET next_sweep_at=clock_timestamp() WHERE tenant_id=1`); err != nil {
		t.Fatal(err)
	}
	if err = s.PruneRetention(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count("old") != 0 {
		t.Fatal("remaining old batch was not pruned")
	}
	var total int
	if err = s.db.QueryRow(`SELECT sum(event_count) FROM uem_audit_retention_history WHERE tenant_id=1 AND source='apple'`).Scan(&total); err != nil || total != 1500 {
		t.Fatal("erasure count duplicated or lost", total, err)
	}
}

func TestRetentionRejectsExpiredAndStaleReviewAndRollsBackErasure(t *testing.T) {
	s := testStore(t, true)
	scope := access.Scope{TenantID: 1}
	first, err := s.PreviewRetention(t.Context(), "organization-admin", scope, 90)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE uem_audit_retention_previews SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyRetention(t.Context(), "organization-admin", scope, first.ID, first.Token); !errors.Is(err, ErrConflict) {
		t.Fatal("expired preview applied", err)
	}
	first, err = s.PreviewRetention(t.Context(), "organization-admin", scope, 90)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.PreviewRetention(t.Context(), "admin", scope, 30)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyRetention(t.Context(), "admin", scope, second.ID, second.Token); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyRetention(t.Context(), "organization-admin", scope, first.ID, first.Token); !errors.Is(err, ErrConflict) {
		t.Fatal("stale preview overwrote policy", err)
	}
	if _, err = s.db.Exec(`INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,created_at) VALUES(1,'fixture','old','device',clock_timestamp()-interval '100 days'); CREATE FUNCTION reject_prune() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='retention.prune' THEN RAISE EXCEPTION 'test failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_prune BEFORE INSERT ON uem_audit_retention_history FOR EACH ROW EXECUTE FUNCTION reject_prune()`); err != nil {
		t.Fatal(err)
	}
	if err = s.PruneRetention(t.Context()); err == nil {
		t.Fatal("erasure committed without evidence")
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE action='old'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("failed erasure did not roll back", err)
	}
	if _, err = s.db.Exec(`DROP TRIGGER reject_prune ON uem_audit_retention_history`); err != nil {
		t.Fatal(err)
	}
	if err = s.PruneRetention(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE action='old'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("erasure could not recover", err)
	}
}
