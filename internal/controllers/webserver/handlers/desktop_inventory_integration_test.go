package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/ent/agent"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/open-uem/openuem-console/internal/views/filters"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func exerciseDesktopInventoryPermissions(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling, otherTenant, otherSite int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	var err error
	h.Audit, err = audit.NewStore(h.Model.DB, h.Access)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.Audit.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = h.Model.Client.Agent.UpdateOneID("windows-fixture").SetNotes("private-inventory-notes").SetDescription("private-inventory-description").SetUpdateTaskResult("private-inventory-task-output").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		id      string
		sites   []int
		waiting bool
	}{
		{"inventory-partial", []int{site}, false},
		{"inventory-sibling", []int{sibling}, false},
		{"inventory-foreign", []int{otherSite}, false},
		{"inventory-ambiguous", []int{site, otherSite}, false},
		{"inventory-two-local-sites", []int{site, sibling}, false},
		{"inventory-orphan", nil, false},
		{"inventory-waiting", []int{site}, true},
	} {
		create := h.Model.Client.Agent.Create().SetID(row.id).SetHostname(row.id).SetOs("windows").AddSiteIDs(row.sites...)
		if !row.waiting {
			create.SetAgentStatus(agent.AgentStatusEnabled)
		}
		if err = create.Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	base := fmt.Sprintf("/tenant/%d/site/%d", tenant, site)
	for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin"} {
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), base} {
			for _, suffix := range []string{"", "/overview", "/hardware", "/os"} {
				rec := request(user, "GET", prefix+"/computers/windows-fixture"+suffix+"?delete=yes&tenant="+fmt.Sprint(otherTenant), nil)
				if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("%s inventory %s%s: %d %s", user, prefix, suffix, rec.Code, rec.Body.String())
				}
				for _, want := range []string{"Computer inventory", "Finance Windows", "Windows 11", "Laptop", "Intel", "14.9 GiB"} {
					if !strings.Contains(rec.Body.String(), want) {
						t.Errorf("inventory missing %q", want)
					}
				}
				for _, forbidden := range []string{"private-inventory-", "Private organization", "Private site", "endpoint-description", "endpoint-type", "Confirm deletion", "/computers/windows-fixture/power", "/computers/windows-fixture/notes", "<dd>finance</dd>"} {
					if strings.Contains(rec.Body.String(), forbidden) {
						t.Errorf("inventory exposes %q", forbidden)
					}
				}
			}
		}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin"} {
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), base} {
			for _, filter := range []string{"", "?platform=windows", "?q=inventory"} {
				rec := request(user, "GET", prefix+"/devices"+filter, nil)
				if rec.Code != 200 {
					t.Fatal("scoped inventory list unavailable", rec.Code, rec.Body.String())
				}
				for _, hidden := range []string{"inventory-ambiguous", "inventory-two-local-sites", "inventory-foreign", "inventory-orphan", "inventory-waiting"} {
					if strings.Contains(rec.Body.String(), hidden) {
						t.Errorf("%s list %s%s exposes %s", user, prefix, filter, hidden)
					}
				}
				if filter == "" && !strings.Contains(rec.Body.String(), `/computers/windows-fixture"`) {
					t.Fatal("scoped inventory link missing")
				}
			}
		}
	}
	if rec := request("apple-console-admin", "GET", base+"/devices", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "inventory-ambiguous") {
		t.Fatal("administrator cannot inspect ambiguous assignments", rec.Code, rec.Body.String())
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin", "apple-console-admin"} {
		principal, err := h.Access.Principal(ctx, user)
		if err != nil {
			t.Fatal(err)
		}
		info := &partials.CommonInfo{TenantID: fmt.Sprint(tenant), SiteID: fmt.Sprint(site), Principal: principal}
		count, err := h.Model.CountAllComputers(filters.AgentFilter{}, info)
		want := 2 // The admitted Windows report and the partial report.
		if principal.IsAdministrator() {
			want = 4 // Administrators can inspect both ambiguous assignments.
		}
		if err != nil || count != want {
			t.Fatal("inventory count exposed hidden assignments", user, count, err)
		}
	}
	if rec := request("scoped-viewer", "GET", base+"/computers/inventory-partial", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "No hardware report received yet.") || !strings.Contains(rec.Body.String(), "No operating system report received yet.") {
		t.Fatal("partial report unavailable", rec.Code, rec.Body.String())
	}
	for _, id := range []string{"inventory-sibling", "inventory-foreign", "inventory-ambiguous", "inventory-two-local-sites", "inventory-orphan", "inventory-waiting", "missing-device"} {
		for _, suffix := range []string{"", "/hardware", "/os"} {
			if rec := request("scoped-viewer", "GET", base+"/computers/"+id+suffix, nil); rec.Code != 404 || strings.Contains(rec.Body.String(), "Computer inventory") {
				t.Errorf("hidden device %s returned %d: %s", id, rec.Code, rec.Body.String())
			}
		}
	}
	for _, id := range []string{"inventory-ambiguous", "inventory-two-local-sites"} {
		if rec := request("organization-admin", "GET", fmt.Sprintf("/tenant/%d/computers/%s", tenant, id), nil); rec.Code != 404 {
			t.Errorf("ambiguous organization device %s returned %d", id, rec.Code)
		}
	}
	for _, prefix := range []string{fmt.Sprintf("/tenant/%d/site/%d", tenant, sibling), fmt.Sprintf("/tenant/%d/site/%d", otherTenant, otherSite)} {
		if rec := request("scoped-viewer", "GET", prefix+"/computers/windows-fixture", nil); rec.Code != 404 {
			t.Errorf("foreign URL scope returned %d", rec.Code)
		}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin"} {
		for _, endpoint := range []struct{ method, suffix string }{{"POST", "/overview"}, {"DELETE", ""}, {"GET", "/notes"}, {"GET", "/remote-assistance"}, {"GET", "/power"}, {"POST", "/software"}, {"POST", "/network-adapters"}, {"POST", "/inventory/network"}, {"POST", "/physical-disks"}, {"POST", "/inventory/storage"}, {"POST", "/logical-disks"}, {"POST", "/logical-disks/file"}, {"PUT", "/logical-disks/file"}, {"DELETE", "/logical-disks/file"}, {"POST", "/logical-disks/downloadfile"}, {"POST", "/logical-disks/downloadfolder"}, {"POST", "/logical-disks/downloadmany"}, {"POST", "/logical-disks/folder"}, {"PUT", "/logical-disks/folder"}, {"DELETE", "/logical-disks/folder"}, {"DELETE", "/logical-disks/many"}, {"POST", "/hardware"}, {"POST", "/os"}, {"POST", "/printers"}, {"POST", "/monitors"}, {"POST", "/inventory/peripherals"}, {"POST", "/inventory/memory"}, {"POST", "/inventory/shares"}, {"POST", "/shares"}} {
			if rec := request(user, endpoint.method, base+"/computers/windows-fixture"+endpoint.suffix, url.Values{"endpoint-description": {"unauthorized-change"}, "tenant": {fmt.Sprint(otherTenant)}, "site": {fmt.Sprint(otherSite)}}); rec.Code != 403 {
				t.Errorf("legacy action %s %s for %s returned %d", endpoint.method, endpoint.suffix, user, rec.Code)
			}
		}
	}
	var count int
	if err = h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE tenant_id=$1 AND site_id=$2 AND actor='scoped-viewer' AND action='inventory.desktop.read' AND resource_id='windows-fixture'`, tenant, site).Scan(&count); err != nil || count != 12 {
		t.Fatal("read audit has incorrect device scope", count, err)
	}
	filter := audit.Filter{Scope: access.Scope{TenantID: tenant, SiteID: site}, Source: "inventory", From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Minute)}
	page, err := h.Audit.List(ctx, "organization-admin", filter, "")
	if err != nil || len(page.Events) != 37 {
		t.Fatal("inventory reads missing from scoped audit", page, err)
	}
	if _, err = h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT inventory_test_failure CHECK(actor<>'scoped-viewer') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = h.Model.DB.ExecContext(context.Background(), `ALTER TABLE uem_inventory_audit DROP CONSTRAINT IF EXISTS inventory_test_failure`)
	})
	for _, suffix := range []string{"", "/hardware", "/os"} {
		if rec := request("scoped-viewer", "GET", base+"/computers/windows-fixture"+suffix, nil); rec.Code != 503 || strings.Contains(rec.Body.String(), "Finance Windows") || strings.Contains(rec.Body.String(), "inventory_test_failure") {
			t.Fatal("audit failure disclosed inventory or database details", rec.Code, rec.Body.String())
		}
	}
	if _, err = h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT inventory_test_failure`); err != nil {
		t.Fatal(err)
	}
	exerciseInventoryPermissionTransaction(t, h, ctx, tenant, site)
}

func exerciseInventoryPermissionTransaction(t *testing.T, h *Handler, ctx context.Context, tenant, site int) {
	t.Helper()
	const actor = "inventory-revocation-reader"
	if err := h.Model.Client.User.Create().SetID(actor).SetName(actor).SetEmail(actor + "@example.test").SetUse2fa(false).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	scope := access.Scope{TenantID: tenant, SiteID: site}
	if err := h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 0, []access.Grant{{Role: access.Viewer, Scope: scope}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	lock, err := h.Model.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err = lock.ExecContext(ctx, `LOCK TABLE uem_inventory_audit IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() {
		_, err := inventory.ReadDesktop(ctx, h.Model.DB, h.Access, actor, scope, "windows-fixture")
		read <- err
	}()
	// Observe the actual pending audit insert before attempting revocation.
	for {
		var pending bool
		if err = h.Model.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation='uem_inventory_audit'::regclass AND NOT granted)`).Scan(&pending); err != nil {
			t.Fatal(err)
		}
		if pending {
			break
		}
		select {
		case err = <-read:
			t.Fatal("read finished before audit", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	revoke := make(chan error, 1)
	go func() { revoke <- h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 1, nil) }()
	select {
	case err = <-revoke:
		t.Fatal("grant replacement overtook uncommitted inventory audit", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err = lock.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-read; err != nil {
		t.Fatal(err)
	}
	if err = <-revoke; err != nil {
		t.Fatal(err)
	}
	if d, err := inventory.ReadDesktop(ctx, h.Model.DB, h.Access, actor, scope, "windows-fixture"); d != nil || !errors.Is(err, access.ErrDenied) {
		t.Fatal("revoked reader received inventory", d, err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if d, err := inventory.ReadDesktop(cancelled, h.Model.DB, h.Access, "scoped-viewer", scope, "windows-fixture"); d != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled request received inventory", d, err)
	}
}
