package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/open-uem/ent/agent"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
)

func newSoftwareFixture(t *testing.T) *refreshFixture {
	t.Helper()
	f := newRefreshFixture(t, nil)
	audits, err := audit.NewStore(f.db, f.permissions)
	if err != nil {
		t.Fatal(err)
	}
	if err = audits.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = audits.Migrate(t.Context()); err != nil {
		t.Fatal("software audit migration is not idempotent", err)
	}
	return f
}

func TestSoftwareInventoryPagesSearchAndAudit(t *testing.T) {
	f := newSoftwareFixture(t)
	for i := 0; i < 27; i++ {
		if err := f.client.App.Create().SetName(fmt.Sprintf("Application %02d", i)).SetVersion("1.2").SetPublisher("Example Publisher").SetInstallDate("20260911").SetOwnerID(f.id).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.client.App.Create().SetName("Literal %_ search").SetVersion("3").SetOwnerID(f.id).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	read := func(filter inventory.SoftwareFilter) *inventory.SoftwarePage {
		t.Helper()
		page, err := inventory.ReadSoftware(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, filter)
		if err != nil {
			t.Fatal(err)
		}
		return page
	}
	first := read(inventory.SoftwareFilter{})
	if len(first.Entries) != 25 || first.Next == 0 || first.DeviceID != f.id || first.SiteID != f.scope.SiteID {
		t.Fatal("first page or scope incorrect", first)
	}
	second := read(inventory.SoftwareFilter{After: first.Next})
	if len(second.Entries) != 3 || second.Next != 0 || second.Entries[0].ID <= first.Next {
		t.Fatal("keyset page repeated or skipped entries", second)
	}
	if got := read(inventory.SoftwareFilter{Search: "%_"}); len(got.Entries) != 1 || got.Entries[0].Name != "Literal %_ search" {
		t.Fatal("search interpreted SQL wildcards", got)
	}
	if got := read(inventory.SoftwareFilter{Search: "pUbLiShEr"}); len(got.Entries) != 25 || got.Next == 0 {
		t.Fatal("publisher search is not bounded or case insensitive", got)
	}
	if got := read(inventory.SoftwareFilter{Search: "' OR true --"}); len(got.Entries) != 0 || got.DeviceID != f.id {
		t.Fatal("literal search changed scope", got)
	}
	if got := read(inventory.SoftwareFilter{After: 9223372036854775807}); len(got.Entries) != 0 || got.Next != 0 {
		t.Fatal("empty final page incorrect", got)
	}
	var count int
	if err := f.db.QueryRow(`SELECT count(*) FROM uem_inventory_audit WHERE actor='viewer' AND tenant_id=$1 AND site_id=$2 AND action='inventory.software.read' AND resource_id=$3`, f.scope.TenantID, f.scope.SiteID, f.id).Scan(&count); err != nil || count != 6 {
		t.Fatal("software reads were not scoped and audited", count, err)
	}
	if err := f.client.Agent.UpdateOneID(f.id).ClearSite().AddSiteIDs(f.otherSite).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, err := inventory.ReadSoftware(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.SoftwareFilter{After: first.Next}); got != nil || !errors.Is(err, inventory.ErrNotFound) {
		t.Fatal("cursor preserved access after a move", got, err)
	}
}

func TestSoftwareInventoryRejectsHiddenObjectsAndRevokedReads(t *testing.T) {
	f := newSoftwareFixture(t)
	read := func() (*inventory.SoftwarePage, error) {
		return inventory.ReadSoftware(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.SoftwareFilter{})
	}
	if got, err := read(); err != nil || got == nil || len(got.Entries) != 0 {
		t.Fatal("empty inventory unavailable", got, err)
	}
	for _, state := range []string{"ambiguous", "waiting", "orphan"} {
		update := f.client.Agent.UpdateOneID(f.id).ClearSite().SetAgentStatus(agent.AgentStatusEnabled)
		if state != "orphan" {
			update.AddSiteIDs(f.scope.SiteID)
		}
		if state == "ambiguous" {
			update.AddSiteIDs(f.otherSite)
		}
		if state == "waiting" {
			update.SetAgentStatus(agent.AgentStatusWaitingForAdmission)
		}
		if err := update.Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got, err := read(); got != nil || !errors.Is(err, inventory.ErrNotFound) {
			t.Fatal("hidden inventory returned", state, got, err)
		}
	}
	if err := f.client.Agent.UpdateOneID(f.id).AddSiteIDs(f.scope.SiteID).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`ALTER TABLE uem_inventory_audit ADD CONSTRAINT software_audit_failure CHECK(action<>'inventory.software.read') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if got, err := read(); got != nil || err == nil {
		t.Fatal("audit failure returned report data", got, err)
	}
	if _, err := f.db.Exec(`ALTER TABLE uem_inventory_audit DROP CONSTRAINT software_audit_failure`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := inventory.ReadSoftware(ctx, f.db, f.permissions, "viewer", f.scope, f.id, inventory.SoftwareFilter{}); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read continued", got, err)
	}
	for _, filter := range []inventory.SoftwareFilter{{After: -1}, {Search: strings.Repeat("x", 257)}, {Search: "line\nbreak"}, {Search: string([]byte{0xff})}} {
		if got, err := inventory.ReadSoftware(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, filter); got != nil || !errors.Is(err, inventory.ErrSoftwareFilter) {
			t.Fatal("invalid filter accepted", got, err)
		}
	}
	if err := f.permissions.ReplaceGrants(t.Context(), "admin", "viewer", 1, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := read(); got != nil || !errors.Is(err, access.ErrDenied) {
		t.Fatal("revoked viewer retained software access", got, err)
	}
}

func TestSoftwareInventoryWithLargeForeignReport(t *testing.T) {
	f := newSoftwareFixture(t)
	if err := f.client.Agent.Create().SetID("large-hidden-report").SetHostname("Hidden report").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.otherSite).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO apps(name,version,agent_apps) SELECT 'Hidden application '||n,'1','large-hidden-report' FROM generate_series(1,50000) n`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO apps(name,version,agent_apps) SELECT 'Visible application '||n,'1',$1 FROM generate_series(1,30) n`, f.id); err != nil {
		t.Fatal(err)
	}
	page, err := inventory.ReadSoftware(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.SoftwareFilter{})
	if err != nil || page == nil || len(page.Entries) != 25 || page.Next == 0 {
		t.Fatal("large foreign report blocked bounded inventory", page, err)
	}
	for _, item := range page.Entries {
		if !strings.HasPrefix(item.Name, "Visible application ") {
			t.Fatal("foreign application entered page", item)
		}
	}
	page, err = inventory.ReadSoftware(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.SoftwareFilter{After: page.Next})
	if err != nil || page == nil || len(page.Entries) != 5 || page.Next != 0 {
		t.Fatal("large inventory continuation failed", page, err)
	}
}
