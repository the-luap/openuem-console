package apple

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func windowsRequestFixture(t *testing.T) (*Store, *access.Store, *SoftwareVersion, string) {
	t.Helper()
	s, p, v, issued, _ := windowsRequestFixtureWithKeys(t)
	return s, p, v, issued.DeviceID
}

func windowsRequestFixtureWithKeys(t *testing.T) (*Store, *access.Store, *SoftwareVersion, *enrollment.Response, *enrollment.Keys) {
	t.Helper()
	return windowsRequestFixtureBeforeMigration(t, "")
}

func windowsRequestFixtureBeforeMigration(t *testing.T, before string) (*Store, *access.Store, *SoftwareVersion, *enrollment.Response, *enrollment.Keys) {
	t.Helper()
	s, permissions := windowsSoftwareStoreBeforeMigration(t, before)
	r, err := registry.NewStore(s.db, "integration-test-master-key-32-bytes-minimum")
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	s.agentRegistry = r
	if _, err = r.EnsureAuthority(t.Context(), 1, "Owned Windows preparation", "https://uem.example.test", "admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	invitation, err := r.Invite(t.Context(), registry.InvitationOptions{Scope: registry.Scope{TenantID: 1, SiteID: 1}, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Broker.Wipe)
	claim, err := keys.Request(invitation.URL[strings.LastIndex(invitation.URL, "/")+1:], "windows", "amd64", "Owned Windows")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := r.Claim(t.Context(), *claim)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`CREATE TABLE agents(oid TEXT PRIMARY KEY,os TEXT NOT NULL,agent_status TEXT NOT NULL,nickname TEXT NOT NULL,hostname TEXT NOT NULL);CREATE TABLE site_agents(agent_id TEXT NOT NULL REFERENCES agents(oid),site_id BIGINT NOT NULL REFERENCES sites(id),PRIMARY KEY(agent_id,site_id));INSERT INTO sites VALUES(3,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO agents VALUES($1,'windows','Enabled','Owned %_ Windows','owned-windows')`, issued.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO site_agents VALUES($1,1)`, issued.DeviceID); err != nil {
		t.Fatal(err)
	}
	version, err := s.PublishWindowsSoftware(t.Context(), Scope{TenantID: 1}, uuid.NewString(), testWindowsSoftware("windows-msi"), "admin", permissions)
	if err != nil {
		t.Fatal(err)
	}
	return s, permissions, version, issued, keys
}

func TestWindowsSoftwareRequestConcurrentIntentAndCancellation(t *testing.T) {
	s, p, v, device := windowsRequestFixture(t)
	scope, request := Scope{TenantID: 1, SiteID: 1}, uuid.NewString()
	results := make(chan *WindowsSoftwareRequest, 6)
	failures := make(chan error, 6)
	var work sync.WaitGroup
	for range 6 {
		work.Go(func() {
			r, e := s.PrepareWindowsSoftware(t.Context(), scope, request, v.ID, device, "install", "operator", p)
			if e != nil {
				failures <- e
			} else {
				results <- r
			}
		})
	}
	work.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	var first *WindowsSoftwareRequest
	for r := range results {
		if first != nil && first.ID != r.ID {
			t.Fatal("retry created another request")
		}
		first = r
	}
	if first == nil || first.Status != "prepared" || first.SiteID != 1 || time.Until(first.ExpiresAt) > time.Hour || time.Until(first.ExpiresAt) < 59*time.Minute {
		t.Fatal("invalid preparation", first)
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE action='software.windows.request.prepare' AND details->>'site_id'='1'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate or unscoped audit", count, err)
	}
	var matches bool
	if err := s.db.QueryRow(`SELECT r.certificate_hash=i.certificate_hash FROM uem_windows_software_requests r JOIN uem_agent_identities i ON i.id=r.agent_id WHERE r.id=$1`, first.ID).Scan(&matches); err != nil || !matches {
		t.Fatal("request lost identity generation", err)
	}
	for _, args := range [][3]string{{request, "remove", "operator"}, {request, "install", "admin"}, {uuid.NewString(), "install", "operator"}} {
		if _, err := s.PrepareWindowsSoftware(t.Context(), scope, args[0], v.ID, device, args[1], args[2], p); !errors.Is(err, ErrConflict) {
			t.Fatal("conflicting intent accepted", args, err)
		}
	}
	other := testWindowsSoftware("windows-exe")
	other.Identifier = "Different.NativeAlias"
	alias, err := s.PublishWindowsSoftware(t.Context(), Scope{TenantID: 1}, uuid.NewString(), other, "admin", p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.PrepareWindowsSoftware(t.Context(), scope, uuid.NewString(), alias.ID, device, "remove", "operator", p); !errors.Is(err, ErrConflict) {
		t.Fatal("native package alias bypassed device reservation", err)
	}
	if err = s.CancelWindowsSoftwarePreparation(t.Context(), scope, v.ID, first.ID, "reader", p); !errors.Is(err, access.ErrDenied) {
		t.Fatal("reader cancelled", err)
	}
	if err = s.CancelWindowsSoftwarePreparation(t.Context(), scope, v.ID, first.ID, "operator", p); err != nil {
		t.Fatal(err)
	}
	if err = s.CancelWindowsSoftwarePreparation(t.Context(), scope, v.ID, first.ID, "operator", p); err != nil {
		t.Fatal("cancel retry", err)
	}
	replay, err := s.PrepareWindowsSoftware(t.Context(), scope, request, v.ID, device, "install", "operator", p)
	if err != nil || replay.Status != "cancelled" || !replay.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatal("replay resurrected intent", replay, err)
	}
	removed, err := s.PrepareWindowsSoftware(t.Context(), scope, uuid.NewString(), v.ID, device, "remove", "operator", p)
	if err != nil || removed.Operation != "remove" {
		t.Fatal("new removal preparation", err)
	}
	if _, err = s.db.Exec(`UPDATE uem_windows_software_requests SET operation='remove' WHERE id=$1`, first.ID); err == nil {
		t.Fatal("immutable intent changed")
	}
	if _, err = s.db.Exec(`UPDATE uem_windows_software_requests SET status='prepared',completed_at=NULL WHERE id=$1`, first.ID); err == nil {
		t.Fatal("terminal history reopened")
	}
	if err = p.ReplaceGrants(t.Context(), "admin", "operator", 1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PrepareWindowsSoftware(t.Context(), scope, request, v.ID, device, "install", "operator", p); !errors.Is(err, access.ErrDenied) {
		t.Fatal("revoked actor replayed", err)
	}
}

func TestWindowsSoftwareRequestRequiresCurrentUnambiguousWindowsScope(t *testing.T) {
	s, p, v, device := windowsRequestFixture(t)
	prepare := func(scope Scope) error {
		_, err := s.PrepareWindowsSoftware(t.Context(), scope, uuid.NewString(), v.ID, device, "install", "admin", p)
		return err
	}
	for _, scope := range []Scope{{TenantID: 2}, {TenantID: 1, SiteID: 3}} {
		if err := prepare(scope); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign scope accepted", err)
		}
	}
	cases := [][2]string{
		{`UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1`, `UPDATE uem_agent_identities SET revoked_at=NULL WHERE id=$1`},
		{`UPDATE uem_agent_identities SET platform='macos' WHERE id=$1`, `UPDATE uem_agent_identities SET platform='windows' WHERE id=$1`},
		{`UPDATE uem_agent_identities SET architecture='arm64' WHERE id=$1`, `UPDATE uem_agent_identities SET architecture='amd64' WHERE id=$1`},
		{`UPDATE agents SET agent_status='WaitingForAdmission' WHERE oid=$1`, `UPDATE agents SET agent_status='Enabled' WHERE oid=$1`},
		{`UPDATE agents SET agent_status='Disabled' WHERE oid=$1`, `UPDATE agents SET agent_status='Enabled' WHERE oid=$1`},
		{`INSERT INTO site_agents VALUES($1,3)`, `DELETE FROM site_agents WHERE agent_id=$1 AND site_id=3`},
		{`UPDATE site_agents SET site_id=3 WHERE agent_id=$1`, `UPDATE site_agents SET site_id=1 WHERE agent_id=$1`},
	}
	for _, test := range cases {
		if _, err := s.db.Exec(test[0], device); err != nil {
			t.Fatal(err)
		}
		if err := prepare(Scope{TenantID: 1}); err == nil {
			t.Fatal("changed authority or inventory accepted", test[0])
		}
		page, err := s.ReadWindowsSoftwareRequests(t.Context(), Scope{TenantID: 1}, v.ID, "", "", "", "admin", p)
		if err != nil || len(page.Targets) != 0 {
			t.Fatal("ineligible endpoint offered", len(page.Targets), err)
		}
		if _, err = s.db.Exec(test[1], device); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{"%_", "owned-windows", device} {
		page, err := s.ReadWindowsSoftwareRequests(t.Context(), Scope{TenantID: 1}, v.ID, q, "", "", "reader", p)
		// The site reader cannot read the broader organization scope.
		if !errors.Is(err, access.ErrDenied) || page != nil {
			t.Fatal("site reader gained organization rights", err)
		}
		page, err = s.ReadWindowsSoftwareRequests(t.Context(), Scope{TenantID: 1, SiteID: 1}, v.ID, q, "", "", "reader", p)
		if err != nil || len(page.Targets) != 1 {
			t.Fatal("literal target search", q, err)
		}
	}
	if err := s.WithdrawSoftwareVersion(t.Context(), Scope{TenantID: 1}, v.ID, "admin", p); err != nil {
		t.Fatal(err)
	}
	if err := prepare(Scope{TenantID: 1}); !errors.Is(err, ErrConflict) {
		t.Fatal("withdrawn approval prepared", err)
	}
}

func TestWindowsSoftwareRequestsFailClosedOnAuditFailure(t *testing.T) {
	s, p, v, device := windowsRequestFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	r, err := s.PrepareWindowsSoftware(t.Context(), scope, uuid.NewString(), v.ID, device, "install", "operator", p)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec(`CREATE FUNCTION reject_windows_request_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action LIKE 'software.windows.request%' THEN RAISE EXCEPTION 'owned audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_windows_request_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_windows_request_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	if page, err := s.ReadWindowsSoftwareRequests(t.Context(), scope, v.ID, "", "", "", "reader", p); err == nil || page != nil {
		t.Fatal("data returned before read audit")
	}
	if err = s.CancelWindowsSoftwarePreparation(t.Context(), scope, v.ID, r.ID, "operator", p); err == nil {
		t.Fatal("cancellation survived failed audit")
	}
	var status string
	if err = s.db.QueryRow(`SELECT status FROM uem_windows_software_requests WHERE id=$1`, r.ID).Scan(&status); err != nil || status != "prepared" {
		t.Fatal("cancellation was not rolled back", status, err)
	}
	if _, err = s.db.Exec(`DROP TRIGGER reject_windows_request_audit ON mdm_apple_audit`); err != nil {
		t.Fatal(err)
	}
	if err = s.CancelWindowsSoftwarePreparation(t.Context(), scope, v.ID, r.ID, "operator", p); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`CREATE TRIGGER reject_windows_request_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_windows_request_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PrepareWindowsSoftware(t.Context(), scope, uuid.NewString(), v.ID, device, "install", "operator", p); err == nil {
		t.Fatal("preparation survived failed audit")
	}
	var pending int
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_windows_software_requests WHERE status='prepared'`).Scan(&pending); err != nil || pending != 0 {
		t.Fatal("failed transaction reserved device", pending, err)
	}
}

func TestWindowsSoftwareRequestsRetainScopedPagedHistory(t *testing.T) {
	s, p, v, device := windowsRequestFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	for range 52 {
		r, err := s.PrepareWindowsSoftware(t.Context(), scope, uuid.NewString(), v.ID, device, "install", "operator", p)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.CancelWindowsSoftwarePreparation(t.Context(), scope, v.ID, r.ID, "operator", p); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.ReadWindowsSoftwareRequests(t.Context(), scope, v.ID, "", "", "", "reader", p)
	if err != nil || len(page.Requests) != 50 || page.NextRequest == "" {
		t.Fatal("first history page", err)
	}
	next, err := s.ReadWindowsSoftwareRequests(t.Context(), scope, v.ID, "", "", page.NextRequest, "reader", p)
	if err != nil || len(next.Requests) != 2 || next.NextRequest != "" {
		t.Fatal("next history page", err)
	}
	foreign, err := s.ReadWindowsSoftwareRequests(t.Context(), Scope{TenantID: 1, SiteID: 3}, v.ID, "", "", page.NextRequest, "admin", p)
	if err != nil || len(foreign.Requests) != 0 {
		t.Fatal("foreign history cursor", err)
	}
	// Historical site visibility and cancellation survive a current scope move;
	// changed current inventory cannot grant mutation authority over the old site.
	if _, err = s.db.Exec(`UPDATE site_agents SET site_id=3 WHERE agent_id=$1`, device); err != nil {
		t.Fatal(err)
	}
	history, err := s.ReadWindowsSoftwareRequests(t.Context(), scope, v.ID, "", "", "", "reader", p)
	if err != nil || len(history.Requests) != 50 || len(history.Targets) != 0 {
		t.Fatal("history was moved with inventory", err)
	}
}

func TestWindowsSoftwareRequestsExpireWithoutDeliveryAndRetainEvidence(t *testing.T) {
	s, p, v, device := windowsRequestFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	old := uuid.NewString()
	// An owned historical writer fixture models a preparation whose service was
	// offline across its deadline. No clock override or device execution is used.
	_, err := s.db.Exec(`INSERT INTO uem_windows_software_requests(id,tenant_id,site_id,agent_id,certificate_hash,package_id,version_id,request_id,operation,actor,created_at,expires_at) SELECT $1,tenant_id,site_id,id,certificate_hash,$2,$3,$4,'install','operator',clock_timestamp()-interval '2 hours',clock_timestamp()-interval '1 hour' FROM uem_agent_identities WHERE id=$5`, old, v.PackageID, v.ID, uuid.NewString(), device)
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.ReadWindowsSoftwareRequests(t.Context(), scope, v.ID, "", "", "", "reader", p)
	if err != nil || len(page.Requests) != 1 || page.Requests[0].Status != "expired" {
		t.Fatal("offline expiration not shown", err)
	}
	if err = s.CancelWindowsSoftwarePreparation(t.Context(), scope, v.ID, old, "operator", p); !errors.Is(err, ErrConflict) {
		t.Fatal("expired work accepted cancellation", err)
	}
	if _, err = s.PrepareWindowsSoftware(t.Context(), scope, uuid.NewString(), v.ID, device, "remove", "operator", p); err != nil {
		t.Fatal("expired preparation retained reservation", err)
	}
	var status string
	var completed *time.Time
	if err = s.db.QueryRow(`SELECT status,completed_at FROM uem_windows_software_requests WHERE id=$1`, old).Scan(&status, &completed); err != nil || status != "expired" || completed == nil {
		t.Fatal("expiry evidence missing", status, err)
	}
	var audits int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE action='software.windows.request.expire' AND resource_id=$1 AND details->>'site_id'='1'`, old).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("expiry audit missing", audits, err)
	}
	for _, query := range []string{`DELETE FROM uem_windows_software_requests`, `TRUNCATE uem_windows_software_requests`, `UPDATE uem_windows_software_requests SET status='prepared',completed_at=NULL WHERE status='expired'`} {
		if _, err = s.db.Exec(query); err == nil {
			t.Fatal("terminal evidence was destroyed", query)
		}
	}
}

func TestWindowsSoftwareRequestDifferentConcurrentIntentsHaveOneWinner(t *testing.T) {
	s, p, v, device := windowsRequestFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	failures := make(chan error, 6)
	var work sync.WaitGroup
	for range 6 {
		work.Go(func() {
			_, err := s.PrepareWindowsSoftware(t.Context(), scope, uuid.NewString(), v.ID, device, "install", "operator", p)
			failures <- err
		})
	}
	work.Wait()
	close(failures)
	winners, conflicts := 0, 0
	for err := range failures {
		if err == nil {
			winners++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if winners != 1 || conflicts != 5 {
		t.Fatal("device reservation race", winners, conflicts)
	}
}

func TestWindowsSoftwareRequestRechecksCertificateAfterAudit(t *testing.T) {
	s, p, v, device := windowsRequestFixture(t)
	// Force expiry at the final transaction boundary, after admission took its
	// identity/inventory locks. Both the audit and preparation must roll back.
	_, err := s.db.Exec(`CREATE FUNCTION expire_windows_identity_on_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='software.windows.request.prepare' THEN UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-interval '1 second'; END IF; RETURN NEW; END $$;CREATE TRIGGER expire_windows_identity_on_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION expire_windows_identity_on_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.PrepareWindowsSoftware(t.Context(), Scope{TenantID: 1, SiteID: 1}, uuid.NewString(), v.ID, device, "install", "operator", p); !errors.Is(err, ErrConflict) {
		t.Fatal("expired final authority committed", err)
	}
	var rows int
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_windows_software_requests`).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("failed authority left a reservation", rows, err)
	}
}
