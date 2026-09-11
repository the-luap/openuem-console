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

func TestMemoryInventoryPagesSearchAndAudit(t *testing.T) {
	f := newSoftwareFixture(t)
	for i := 0; i < 27; i++ {
		if err := f.client.MemorySlot.Create().SetSlot(fmt.Sprintf("Slot %02d", i)).SetSize("16 GB").SetType("DDR5").SetSerialNumber("Serial-AB").SetPartNumber("Part-AB").SetSpeed("4800 MT/s").SetManufacturer("Example Modules").SetOwnerID(f.id).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.client.MemorySlot.Create().SetSlot("Literal %_ search").SetOwnerID(f.id).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	read := func(filter inventory.MemoryFilter) *inventory.MemoryPage {
		t.Helper()
		page, err := inventory.ReadMemory(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, filter)
		if err != nil {
			t.Fatal(err)
		}
		return page
	}
	first := read(inventory.MemoryFilter{})
	if len(first.Entries) != 25 || first.Next == 0 || first.DeviceID != f.id || first.SiteID != f.scope.SiteID {
		t.Fatal("first page or scope incorrect", first)
	}
	second := read(inventory.MemoryFilter{After: first.Next})
	if len(second.Entries) != 3 || second.Next != 0 || second.Entries[0].ID <= first.Next {
		t.Fatal("keyset page repeated or skipped entries", second)
	}
	if got := read(inventory.MemoryFilter{Search: "%_"}); len(got.Entries) != 1 || got.Entries[0].Name != "Literal %_ search" {
		t.Fatal("search interpreted SQL wildcards", got)
	}
	if got := read(inventory.MemoryFilter{Search: "pArT-ab"}); len(got.Entries) != 25 || got.Next == 0 {
		t.Fatal("part-number search is not bounded or case insensitive", got)
	}
	if got := read(inventory.MemoryFilter{Search: "' OR true --"}); len(got.Entries) != 0 || got.DeviceID != f.id {
		t.Fatal("literal search changed scope", got)
	}
	if got := read(inventory.MemoryFilter{After: 9223372036854775807}); len(got.Entries) != 0 || got.Next != 0 {
		t.Fatal("empty final page incorrect", got)
	}
	if got := read(inventory.MemoryFilter{Search: "sLoT 01"}); len(got.Entries) != 1 || got.Entries[0].Name != "Slot 01" {
		t.Fatal("slot name search failed", got)
	}
	if got := read(inventory.MemoryFilter{Search: "eXaMpLe"}); len(got.Entries) != 25 || got.Next == 0 {
		t.Fatal("manufacturer search is not bounded or case insensitive", got)
	}
	if got := read(inventory.MemoryFilter{Search: "sErIaL-ab"}); len(got.Entries) != 25 || got.Next == 0 {
		t.Fatal("serial search is not bounded or case insensitive", got)
	}
	item := first.Entries[0]
	if item.Size != "16 GB" || item.Type != "DDR5" || item.Serial != "Serial-AB" || item.PartNumber != "Part-AB" || item.Speed != "4800 MT/s" || item.Manufacturer != "Example Modules" {
		t.Fatal("reported memory projection changed", item)
	}
	var count int
	if err := f.db.QueryRow(`SELECT count(*) FROM uem_inventory_audit WHERE actor='viewer' AND tenant_id=$1 AND site_id=$2 AND action='inventory.memory.read' AND resource_id=$3`, f.scope.TenantID, f.scope.SiteID, f.id).Scan(&count); err != nil || count != 9 {
		t.Fatal("memory reads were not scoped and audited", count, err)
	}
	if err := f.client.Agent.UpdateOneID(f.id).ClearSite().AddSiteIDs(f.otherSite).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, err := inventory.ReadMemory(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.MemoryFilter{After: first.Next}); got != nil || !errors.Is(err, inventory.ErrNotFound) {
		t.Fatal("cursor preserved access after a move", got, err)
	}
}

func TestMemoryInventoryRejectsHiddenObjectsAndRevokedReads(t *testing.T) {
	f := newSoftwareFixture(t)
	read := func() (*inventory.MemoryPage, error) {
		return inventory.ReadMemory(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.MemoryFilter{})
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
	if _, err := f.db.Exec(`ALTER TABLE uem_inventory_audit ADD CONSTRAINT memory_audit_failure CHECK(action<>'inventory.memory.read') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if got, err := read(); got != nil || err == nil {
		t.Fatal("audit failure returned report data", got, err)
	}
	if _, err := f.db.Exec(`ALTER TABLE uem_inventory_audit DROP CONSTRAINT memory_audit_failure`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := inventory.ReadMemory(ctx, f.db, f.permissions, "viewer", f.scope, f.id, inventory.MemoryFilter{}); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read continued", got, err)
	}
	for _, filter := range []inventory.MemoryFilter{{After: -1}, {Search: strings.Repeat("x", 257)}, {Search: "line\nbreak"}, {Search: string([]byte{0xff})}} {
		if got, err := inventory.ReadMemory(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, filter); got != nil || !errors.Is(err, inventory.ErrMemoryFilter) {
			t.Fatal("invalid filter accepted", got, err)
		}
	}
	if err := f.permissions.ReplaceGrants(t.Context(), "admin", "viewer", 1, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := read(); got != nil || !errors.Is(err, access.ErrDenied) {
		t.Fatal("revoked viewer retained memory access", got, err)
	}
}

func TestMemoryInventoryWithLargeForeignReport(t *testing.T) {
	f := newSoftwareFixture(t)
	if err := f.client.Agent.Create().SetID("large-hidden-report").SetHostname("Hidden report").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.otherSite).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO memory_slots(slot,agent_memoryslots) SELECT 'Hidden slot '||n,'large-hidden-report' FROM generate_series(1,50000) n`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO memory_slots(slot,agent_memoryslots) SELECT 'Visible slot '||n,$1 FROM generate_series(1,30) n`, f.id); err != nil {
		t.Fatal(err)
	}
	page, err := inventory.ReadMemory(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.MemoryFilter{})
	if err != nil || page == nil || len(page.Entries) != 25 || page.Next == 0 {
		t.Fatal("large foreign report blocked bounded inventory", page, err)
	}
	for _, item := range page.Entries {
		if !strings.HasPrefix(item.Name, "Visible slot ") {
			t.Fatal("foreign slot entered page", item)
		}
	}
	page, err = inventory.ReadMemory(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.MemoryFilter{After: page.Next})
	if err != nil || page == nil || len(page.Entries) != 5 || page.Next != 0 {
		t.Fatal("large inventory continuation failed", page, err)
	}
}

func TestMemoryInventoryPreservesAbsentValues(t *testing.T) {
	f := newSoftwareFixture(t)
	if err := f.client.MemorySlot.Create().SetOwnerID(f.id).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	page, err := inventory.ReadMemory(t.Context(), f.db, f.permissions, "operator", f.scope, f.id, inventory.MemoryFilter{})
	if err != nil || page == nil || len(page.Entries) != 1 {
		t.Fatal("operator memory report unavailable", page, err)
	}
	item := page.Entries[0]
	if item.Name != "" || item.Size != "" || item.Type != "" || item.Serial != "" || item.PartNumber != "" || item.Speed != "" || item.Manufacturer != "" {
		t.Fatal("missing memory report fields were invented", item)
	}
	var index string
	if err := f.db.QueryRow(`SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname='uem_inventory_memory_cursor'`).Scan(&index); err != nil || !strings.Contains(index, "(agent_memoryslots, id)") {
		t.Fatal("memory cursor index missing", index, err)
	}
}
