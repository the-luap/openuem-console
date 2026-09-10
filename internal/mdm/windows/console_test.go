package windows

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestWindowsConsoleScopePaginationSearchAndAudit(t *testing.T) {
	f := syncMLTestStore(t)
	s := f.store
	ctx := t.Context()
	scope := f.identity.Scope
	for _, actor := range []string{"admin", "operator", "viewer"} {
		rows, err := s.Devices(ctx, actor, scope, "", 0, 25)
		if err != nil || len(rows) != 1 || rows[0].ID != f.identity.DeviceID || rows[0].RevokedAt != nil {
			t.Fatal("scoped device list failed", err)
		}
		d, err := s.Device(ctx, actor, scope, rows[0].ID)
		if err != nil || d.Name != rows[0].Name || d.FingerprintSHA256 != f.identity.FingerprintSHA256 {
			t.Fatal("device details changed", err)
		}
		for _, search := range []string{strings.ToUpper(d.ID), strings.ToLower(d.Name)} {
			rows, err := s.Devices(ctx, actor, scope, search, 0, 25)
			if err != nil || len(rows) != 1 {
				t.Fatal("literal device search failed", err)
			}
		}
		if rows, err := s.Devices(ctx, actor, scope, "%", 0, 25); err != nil || len(rows) != 0 {
			t.Fatal("search interpreted a SQL wildcard")
		}
		if rows, err := s.Devices(ctx, actor, scope, "", 1, 25); err != nil || len(rows) != 0 {
			t.Fatal("device offset failed")
		}
	}
	for _, actor := range []string{"foreign", "missing", ""} {
		if _, err := s.Devices(ctx, actor, scope, "", 0, 25); err == nil {
			t.Fatal("foreign device list admitted")
		}
		if _, err := s.Device(ctx, actor, scope, f.identity.DeviceID); err == nil {
			t.Fatal("foreign device read admitted")
		}
	}
	for _, other := range []access.Scope{{TenantID: 1, SiteID: 12}, {TenantID: 2, SiteID: 21}, {TenantID: 2, SiteID: 11}, {TenantID: 1}} {
		if _, err := s.Device(ctx, "operator", other, f.identity.DeviceID); err == nil {
			t.Fatal("scope substitution admitted")
		}
	}
	for _, actor := range []string{"viewer", "foreign", "missing"} {
		if _, err := s.EnrollmentInvitations(ctx, actor, scope, 0, 25); err == nil {
			t.Fatal("invitation usernames leaked to unprivileged actor")
		}
		if _, err := s.EnrollmentAvailable(ctx, actor, scope); err == nil {
			t.Fatal("issuer status leaked to unprivileged actor")
		}
	}
	for range 2 {
		createTestInvitation(t, s, "operator")
	}
	first, err := s.EnrollmentInvitations(ctx, "operator", scope, 0, 2)
	if err != nil || len(first) != 2 {
		t.Fatal("invitation page failed", err)
	}
	second, err := s.EnrollmentInvitations(ctx, "operator", scope, 2, 2)
	if err != nil || len(second) != 1 || second[0].ID == first[0].ID || second[0].ID == first[1].ID {
		t.Fatal("invitation pagination overlapped", err)
	}
	if available, err := s.EnrollmentAvailable(ctx, "operator", scope); err != nil || !available {
		t.Fatal("enrollment authority status unavailable", err)
	}
	if available, err := s.EnrollmentAvailable(ctx, "admin", access.Scope{TenantID: 2, SiteID: 21}); err != nil || available {
		t.Fatal("missing authority appeared ready", err)
	}
	for _, page := range [][2]int{{-1, 1}, {100001, 1}, {0, 0}, {0, 101}} {
		if _, err := s.Devices(ctx, "admin", scope, "", page[0], page[1]); !errors.Is(err, ErrConsoleInput) {
			t.Fatal("unbounded device page admitted")
		}
		if _, err := s.EnrollmentInvitations(ctx, "admin", scope, page[0], page[1]); !errors.Is(err, ErrConsoleInput) {
			t.Fatal("unbounded invitation page admitted")
		}
	}
	for _, search := range []string{strings.Repeat("x", 129), "bad\nsearch", string([]byte{0xff})} {
		if _, err := s.Devices(ctx, "admin", scope, search, 0, 1); !errors.Is(err, ErrConsoleInput) {
			t.Fatal("invalid search admitted")
		}
	}
	var audit string
	if err := s.db.QueryRow(`SELECT json_agg(a)::text FROM mdm_windows_console_audit a`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"synthetic@example.test", f.secrets.ClientSecret, f.secrets.ServerSecret, "SYNTHETIC-WINDOWS"} {
		if strings.Contains(audit, private) {
			t.Fatal("console audit leaked protected data")
		}
	}
	for _, statement := range []string{`UPDATE mdm_windows_console_audit SET actor='other'`, `DELETE FROM mdm_windows_console_audit`} {
		if _, err := s.db.Exec(statement); err == nil {
			t.Fatal("console audit was mutable")
		}
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal("console migration not idempotent", err)
	}
}

func TestWindowsConsoleAuditFailureRollsBackReadAndRevocation(t *testing.T) {
	f := syncMLTestStore(t)
	s := f.store
	if _, err := s.db.Exec(`CREATE FUNCTION fail_windows_console_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic private audit failure'; END $$; CREATE TRIGGER fail_windows_console_audit BEFORE INSERT ON mdm_windows_console_audit FOR EACH ROW EXECUTE FUNCTION fail_windows_console_audit()`); err != nil {
		t.Fatal(err)
	}
	if rows, err := s.Devices(t.Context(), "viewer", f.identity.Scope, "", 0, 25); err == nil || rows != nil {
		t.Fatal("device list returned without audit")
	}
	if d, err := s.Device(t.Context(), "viewer", f.identity.Scope, f.identity.DeviceID); err == nil || d != nil {
		t.Fatal("device read returned without audit")
	}
	if rows, err := s.EnrollmentInvitations(t.Context(), "operator", f.identity.Scope, 0, 25); err == nil || rows != nil {
		t.Fatal("invitation list returned without audit")
	}
	if _, err := s.EnrollmentAvailable(t.Context(), "operator", f.identity.Scope); err == nil {
		t.Fatal("issuer status returned without audit")
	}
	if err := s.RevokeDevice(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID); err == nil {
		t.Fatal("revocation committed without audit")
	}
	if _, err := s.AuthenticateManagementDevice(managementTestRequest(t, f.certificate.Raw, f.options), f.options); err != nil {
		t.Fatal("failed audit retained revocation", err)
	}
}

func TestWindowsConsoleOrganizationInventoryChecksLiveSiteOwnership(t *testing.T) {
	f := syncMLTestStore(t)
	s := f.store
	organization := access.Scope{TenantID: f.identity.TenantID}
	for _, actor := range []string{"operator", "viewer", "foreign"} {
		if rows, err := s.Devices(t.Context(), actor, organization, "", 0, 25); !errors.Is(err, access.ErrDenied) || rows != nil {
			t.Fatal("site grant escaped into organization inventory", actor, err)
		}
	}
	if rows, err := s.Devices(t.Context(), "admin", organization, "", 0, 25); err != nil || len(rows) != 1 || rows[0].ID != f.identity.DeviceID {
		t.Fatal("organization inventory omitted native identity", err)
	}
	for _, scope := range []access.Scope{{TenantID: 1, SiteID: 12}, {TenantID: 2}} {
		if rows, err := s.Devices(t.Context(), "admin", scope, "", 0, 25); err != nil || len(rows) != 0 {
			t.Fatal("native identity leaked outside its scope", err)
		}
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_windows_console_audit WHERE tenant_id=1 AND site_id=0 AND site_ref IS NULL AND action='devices.list'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("organization read was not audited", count, err)
	}
	if _, err := s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=11`); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []access.Scope{organization, {TenantID: 2}} {
		if rows, err := s.Devices(t.Context(), "admin", scope, "", 0, 25); err != nil || len(rows) != 0 {
			t.Fatal("site move transferred or retained native identity", err)
		}
	}
	if rows, err := s.Devices(t.Context(), "admin", f.identity.Scope, "", 0, 25); err == nil || rows != nil {
		t.Fatal("stale concrete site remained readable")
	}
}

func TestWindowsConsoleRevocationWaitsForInFlightIdentityAndBlocksReplay(t *testing.T) {
	f := syncMLTestStore(t)
	s := f.store
	scope := f.identity.Scope
	initial := f.initial(t)
	if _, err := f.process(initial); err != nil {
		t.Fatal(err)
	}
	for _, actor := range []string{"operator", "viewer", "foreign"} {
		if err := s.RevokeDevice(t.Context(), actor, scope, f.identity.DeviceID); err == nil {
			t.Fatal("unprivileged revocation admitted")
		}
	}
	lock, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err := lock.Exec(`SELECT id FROM mdm_windows_devices WHERE id=$1 FOR SHARE`, f.identity.DeviceID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	err = s.RevokeDevice(ctx, "admin", scope, f.identity.DeviceID)
	cancel()
	if err == nil {
		t.Fatal("revocation bypassed in-flight identity lock")
	}
	if err := lock.Rollback(); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if err := s.RevokeDevice(t.Context(), "admin", scope, f.identity.DeviceID); err != nil {
				t.Error("concurrent revocation failed", err)
			}
		})
	}
	group.Wait()
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_windows_console_audit WHERE action='device.revoked' AND resource_id=$1`, f.identity.DeviceID).Scan(&count); err != nil || count != 1 {
		t.Fatal("revocation was not idempotent", count, err)
	}
	if _, err := s.AuthenticateManagementDevice(managementTestRequest(t, f.certificate.Raw, f.options), f.options); !errors.Is(err, ErrManagementIdentity) {
		t.Fatal("revoked device authenticated", err)
	}
	if _, err := s.processSyncML(t.Context(), f.certificate, initial, f.options); !errors.Is(err, ErrManagementIdentity) {
		t.Fatal("revoked device replayed stored response", err)
	}
	if d, err := s.Device(t.Context(), "viewer", scope, f.identity.DeviceID); err != nil || d.RevokedAt == nil {
		t.Fatal("revoked device history disappeared", err)
	}
}
