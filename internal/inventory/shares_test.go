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
)

func TestSharesInventoryPagesSearchAndAudit(t *testing.T) {
	f := newSoftwareFixture(t)
	for i := 0; i < 27; i++ {
		if err := f.client.Share.Create().SetName(fmt.Sprintf("Share %02d", i)).SetDescription("Example team files").SetPath(`\\server\Path-Report`).SetOwnerID(f.id).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.client.Share.Create().SetName("Literal %_ search").SetDescription("Literal description").SetOwnerID(f.id).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	read := func(filter inventory.SharesFilter) *inventory.SharesPage {
		t.Helper()
		page, err := inventory.ReadShares(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, filter)
		if err != nil {
			t.Fatal(err)
		}
		return page
	}
	first := read(inventory.SharesFilter{})
	if len(first.Entries) != 25 || first.Next == 0 || first.DeviceID != f.id || first.SiteID != f.scope.SiteID {
		t.Fatal("first page or scope incorrect", first)
	}
	second := read(inventory.SharesFilter{After: first.Next})
	if len(second.Entries) != 3 || second.Next != 0 || second.Entries[0].ID <= first.Next {
		t.Fatal("keyset page repeated or skipped entries", second)
	}
	if got := read(inventory.SharesFilter{Search: "%_"}); len(got.Entries) != 1 || got.Entries[0].Name != "Literal %_ search" {
		t.Fatal("search interpreted SQL wildcards", got)
	}
	if got := read(inventory.SharesFilter{Search: "pAtH-rEpOrT"}); len(got.Entries) != 25 || got.Next == 0 {
		t.Fatal("path search is not bounded or case insensitive", got)
	}
	if got := read(inventory.SharesFilter{Search: "' OR true --"}); len(got.Entries) != 0 || got.DeviceID != f.id {
		t.Fatal("literal search changed scope", got)
	}
	if got := read(inventory.SharesFilter{After: 9223372036854775807}); len(got.Entries) != 0 || got.Next != 0 {
		t.Fatal("empty final page incorrect", got)
	}
	if got := read(inventory.SharesFilter{Search: "sHaRe 01"}); len(got.Entries) != 1 || got.Entries[0].Name != "Share 01" {
		t.Fatal("share name search failed", got)
	}
	if got := read(inventory.SharesFilter{Search: "eXaMpLe"}); len(got.Entries) != 25 || got.Next == 0 {
		t.Fatal("description search is not bounded or case insensitive", got)
	}

	item := first.Entries[0]
	if item.Description != "Example team files" || item.Path != `\\server\Path-Report` {
		t.Fatal("reported share projection changed", item)
	}
	var count int
	if err := f.db.QueryRow(`SELECT count(*) FROM uem_inventory_audit WHERE actor='viewer' AND tenant_id=$1 AND site_id=$2 AND action='inventory.shares.read' AND resource_id=$3`, f.scope.TenantID, f.scope.SiteID, f.id).Scan(&count); err != nil || count != 8 {
		t.Fatal("shares reads were not scoped and audited", count, err)
	}
	if err := f.client.Agent.UpdateOneID(f.id).ClearSite().AddSiteIDs(f.otherSite).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, err := inventory.ReadShares(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.SharesFilter{After: first.Next}); got != nil || !errors.Is(err, inventory.ErrNotFound) {
		t.Fatal("cursor preserved access after a move", got, err)
	}
}

func TestSharesInventoryRejectsHiddenObjectsAndRevokedReads(t *testing.T) {
	f := newSoftwareFixture(t)
	read := func() (*inventory.SharesPage, error) {
		return inventory.ReadShares(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.SharesFilter{})
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
	if _, err := f.db.Exec(`ALTER TABLE uem_inventory_audit ADD CONSTRAINT shares_audit_failure CHECK(action<>'inventory.shares.read') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if got, err := read(); got != nil || err == nil {
		t.Fatal("audit failure returned report data", got, err)
	}
	if _, err := f.db.Exec(`ALTER TABLE uem_inventory_audit DROP CONSTRAINT shares_audit_failure`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := inventory.ReadShares(ctx, f.db, f.permissions, "viewer", f.scope, f.id, inventory.SharesFilter{}); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read continued", got, err)
	}
	for _, filter := range []inventory.SharesFilter{{After: -1}, {Search: strings.Repeat("x", 257)}, {Search: "line\nbreak"}, {Search: string([]byte{0xff})}} {
		if got, err := inventory.ReadShares(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, filter); got != nil || !errors.Is(err, inventory.ErrSharesFilter) {
			t.Fatal("invalid filter accepted", got, err)
		}
	}
	if err := f.permissions.ReplaceGrants(t.Context(), "admin", "viewer", 1, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := read(); got != nil || !errors.Is(err, access.ErrDenied) {
		t.Fatal("revoked viewer retained shares access", got, err)
	}
}

func TestSharesInventoryWithLargeForeignReport(t *testing.T) {
	f := newSoftwareFixture(t)
	if err := f.client.Agent.Create().SetID("large-hidden-report").SetHostname("Hidden report").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.otherSite).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO shares(name,description,agent_shares) SELECT 'Hidden share '||n,'Hidden description','large-hidden-report' FROM generate_series(1,50000) n`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO shares(name,description,agent_shares) SELECT 'Visible share '||n,'',$1 FROM generate_series(1,30) n`, f.id); err != nil {
		t.Fatal(err)
	}
	page, err := inventory.ReadShares(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.SharesFilter{})
	if err != nil || page == nil || len(page.Entries) != 25 || page.Next == 0 {
		t.Fatal("large foreign report blocked bounded inventory", page, err)
	}
	for _, item := range page.Entries {
		if !strings.HasPrefix(item.Name, "Visible share ") {
			t.Fatal("foreign share entered page", item)
		}
	}
	page, err = inventory.ReadShares(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.SharesFilter{After: page.Next})
	if err != nil || page == nil || len(page.Entries) != 5 || page.Next != 0 {
		t.Fatal("large inventory continuation failed", page, err)
	}
}

func TestSharesInventoryPreservesAbsentValues(t *testing.T) {
	f := newSoftwareFixture(t)
	if err := f.client.Share.Create().SetName("").SetDescription("").SetOwnerID(f.id).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	page, err := inventory.ReadShares(t.Context(), f.db, f.permissions, "operator", f.scope, f.id, inventory.SharesFilter{})
	if err != nil || page == nil || len(page.Entries) != 1 {
		t.Fatal("operator shares report unavailable", page, err)
	}
	item := page.Entries[0]
	if item.Name != "" || item.Description != "" || item.Path != "" {
		t.Fatal("missing share report fields were invented", item)
	}
	var index string
	if err := f.db.QueryRow(`SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname='uem_inventory_shares_cursor'`).Scan(&index); err != nil || !strings.Contains(index, "(agent_shares, id)") {
		t.Fatal("shares cursor index missing", index, err)
	}
}
