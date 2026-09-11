package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/ent/agent"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestSecurityInventoryPagesSearchAndAudit(t *testing.T) {
	f := newSoftwareFixture(t)
	for i := 0; i < 27; i++ {
		if err := f.client.Update.Create().SetTitle(fmt.Sprintf("Update %02d", i)).SetDate(time.Date(2026, 9, 1, 12, 34, 56, 123456000, time.UTC)).SetSupportURL("https://updates.invalid/Path-Report").SetOwnerID(f.id).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.client.Update.Create().SetTitle("Literal %_ search").SetDate(time.Time{}).SetOwnerID(f.id).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	read := func(filter inventory.SecurityFilter) *inventory.SecurityPage {
		t.Helper()
		page, err := inventory.ReadSecurity(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, filter)
		if err != nil {
			t.Fatal(err)
		}
		return page
	}
	first := read(inventory.SecurityFilter{})
	if len(first.Entries) != 25 || first.Next == 0 || first.DeviceID != f.id || first.SiteID != f.scope.SiteID {
		t.Fatal("first page or scope incorrect", first)
	}
	second := read(inventory.SecurityFilter{After: first.Next})
	if len(second.Entries) != 3 || second.Next != 0 || second.Entries[0].ID <= first.Next {
		t.Fatal("keyset page repeated or skipped entries", second)
	}
	if got := read(inventory.SecurityFilter{Search: "%_"}); len(got.Entries) != 1 || got.Entries[0].Title != "Literal %_ search" {
		t.Fatal("search interpreted SQL wildcards", got)
	}
	if got := read(inventory.SecurityFilter{Search: "pAtH-rEpOrT"}); len(got.Entries) != 25 || got.Next == 0 {
		t.Fatal("support URL search is not bounded or case insensitive", got)
	}
	if got := read(inventory.SecurityFilter{Search: "' OR true --"}); len(got.Entries) != 0 || got.DeviceID != f.id {
		t.Fatal("literal search changed scope", got)
	}
	if got := read(inventory.SecurityFilter{After: 9223372036854775807}); len(got.Entries) != 0 || got.Next != 0 {
		t.Fatal("empty final page incorrect", got)
	}
	if got := read(inventory.SecurityFilter{Search: "uPdAtE 01"}); len(got.Entries) != 1 || got.Entries[0].Title != "Update 01" {
		t.Fatal("update title search failed", got)
	}

	item := first.Entries[0]
	if item.SupportURL != "https://updates.invalid/Path-Report" || item.Date == nil || !item.Date.Equal(time.Date(2026, 9, 1, 12, 34, 56, 123456000, time.UTC)) {
		t.Fatal("reported update projection changed", item)
	}
	var count int
	if err := f.db.QueryRow(`SELECT count(*) FROM uem_inventory_audit WHERE actor='viewer' AND tenant_id=$1 AND site_id=$2 AND action='inventory.security.read' AND resource_id=$3`, f.scope.TenantID, f.scope.SiteID, f.id).Scan(&count); err != nil || count != 7 {
		t.Fatal("security reads were not scoped and audited", count, err)
	}
	if err := f.client.Agent.UpdateOneID(f.id).ClearSite().AddSiteIDs(f.otherSite).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, err := inventory.ReadSecurity(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.SecurityFilter{After: first.Next}); got != nil || !errors.Is(err, inventory.ErrNotFound) {
		t.Fatal("cursor preserved access after a move", got, err)
	}
}

func TestSecurityInventoryRejectsHiddenObjectsAndRevokedReads(t *testing.T) {
	f := newSoftwareFixture(t)
	read := func() (*inventory.SecurityPage, error) {
		return inventory.ReadSecurity(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.SecurityFilter{})
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
	if _, err := f.db.Exec(`ALTER TABLE uem_inventory_audit ADD CONSTRAINT security_audit_failure CHECK(action<>'inventory.security.read') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if got, err := read(); got != nil || err == nil {
		t.Fatal("audit failure returned report data", got, err)
	}
	if _, err := f.db.Exec(`ALTER TABLE uem_inventory_audit DROP CONSTRAINT security_audit_failure`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := inventory.ReadSecurity(ctx, f.db, f.permissions, "viewer", f.scope, f.id, inventory.SecurityFilter{}); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read continued", got, err)
	}
	for _, filter := range []inventory.SecurityFilter{{After: -1}, {Search: strings.Repeat("x", 257)}, {Search: "line\nbreak"}, {Search: string([]byte{0xff})}} {
		if got, err := inventory.ReadSecurity(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, filter); got != nil || !errors.Is(err, inventory.ErrSecurityFilter) {
			t.Fatal("invalid filter accepted", got, err)
		}
	}
	if err := f.permissions.ReplaceGrants(t.Context(), "admin", "viewer", 1, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := read(); got != nil || !errors.Is(err, access.ErrDenied) {
		t.Fatal("revoked viewer retained security access", got, err)
	}
}

func TestSecurityInventoryWithLargeForeignReport(t *testing.T) {
	f := newSoftwareFixture(t)
	if err := f.client.Agent.Create().SetID("large-hidden-report").SetHostname("Hidden report").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.otherSite).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Antivirus.Create().SetName("Foreign antivirus").SetIsActive(true).SetIsUpdated(true).SetOwnerID("large-hidden-report").Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := f.client.SystemUpdate.Create().SetSystemUpdateStatus("Foreign update status").SetLastInstall(time.Now()).SetLastSearch(time.Now()).SetPendingUpdates(true).SetOwnerID("large-hidden-report").Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO updates(title,date,agent_updates) SELECT 'Hidden update '||n,clock_timestamp(),'large-hidden-report' FROM generate_series(1,50000) n`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO updates(title,date,agent_updates) SELECT 'Visible update '||n,clock_timestamp(),$1 FROM generate_series(1,30) n`, f.id); err != nil {
		t.Fatal(err)
	}
	page, err := inventory.ReadSecurity(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.SecurityFilter{})
	if err != nil || page == nil || len(page.Entries) != 25 || page.Next == 0 {
		t.Fatal("large foreign report blocked bounded inventory", page, err)
	}
	if page.AntivirusName != "" || page.AntivirusActive != nil || page.AntivirusUpdated != nil || page.UpdateStatus != "" || page.PendingUpdates != nil || page.LastInstall != nil || page.LastSearch != nil {
		t.Fatal("foreign security status entered inventory", page)
	}
	for _, item := range page.Entries {
		if !strings.HasPrefix(item.Title, "Visible update ") {
			t.Fatal("foreign update entered page", item)
		}
	}
	page, err = inventory.ReadSecurity(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.SecurityFilter{After: page.Next})
	if err != nil || page == nil || len(page.Entries) != 5 || page.Next != 0 {
		t.Fatal("large inventory continuation failed", page, err)
	}
}

func TestSecurityInventoryPreservesAbsentValues(t *testing.T) {
	f := newSoftwareFixture(t)
	if err := f.client.Update.Create().SetTitle("").SetDate(time.Time{}).SetOwnerID(f.id).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	page, err := inventory.ReadSecurity(t.Context(), f.db, f.permissions, "operator", f.scope, f.id, inventory.SecurityFilter{})
	if err != nil || page == nil || len(page.Entries) != 1 {
		t.Fatal("operator security report unavailable", page, err)
	}
	item := page.Entries[0]
	if item.Title != "" || item.SupportURL != "" || item.Date == nil || !item.Date.IsZero() {
		t.Fatal("missing update report fields were invented", item)
	}
	if page.AntivirusName != "" || page.AntivirusActive != nil || page.AntivirusUpdated != nil || page.UpdateStatus != "" || page.LastInstall != nil || page.LastSearch != nil || page.PendingUpdates != nil {
		t.Fatal("absent security reports became observations", page)
	}
	var index string
	if err := f.db.QueryRow(`SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname='uem_inventory_security_cursor'`).Scan(&index); err != nil || !strings.Contains(index, "(agent_updates, id)") {
		t.Fatal("security cursor index missing", index, err)
	}
}

func TestSecurityInventoryPreservesReportedFlagsAndDates(t *testing.T) {
	f := newSoftwareFixture(t)
	instant := time.Date(2026, 9, 1, 12, 34, 56, 123456000, time.FixedZone("report", 3600))
	av, err := f.client.Antivirus.Create().SetName(`<script>reported product</script>`).SetIsActive(false).SetIsUpdated(false).SetOwnerID(f.id).Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	updates, err := f.client.SystemUpdate.Create().SetSystemUpdateStatus("unknown & custom status").SetLastInstall(instant).SetLastSearch(time.Time{}).SetPendingUpdates(false).SetOwnerID(f.id).Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []bool{false, true} {
		if err = av.Update().SetIsActive(value).SetIsUpdated(!value).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err = updates.Update().SetPendingUpdates(value).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		page, err := inventory.ReadSecurity(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.SecurityFilter{Search: "no history"})
		if err != nil || page == nil {
			t.Fatal("security status without history unavailable", err)
		}
		if page.AntivirusName != `<script>reported product</script>` || page.AntivirusActive == nil || *page.AntivirusActive != value || page.AntivirusUpdated == nil || *page.AntivirusUpdated == value || page.PendingUpdates == nil || *page.PendingUpdates != value {
			t.Fatal("stored security flags or product changed", page)
		}
		if page.UpdateStatus != "unknown & custom status" || page.LastInstall == nil || !page.LastInstall.Equal(instant) || page.LastSearch == nil || !page.LastSearch.IsZero() || len(page.Entries) != 0 {
			t.Fatal("stored status, timestamps or empty history changed", page)
		}
	}
}
