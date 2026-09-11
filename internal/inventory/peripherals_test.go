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

func TestPeripheralsInventoryPagesSearchProjectionAndAudit(t *testing.T) {
	for _, kind := range []inventory.PeripheralsKind{inventory.MonitorReports, inventory.PrinterReports} {
		t.Run(string(kind), func(t *testing.T) {
			f := newSoftwareFixture(t)
			for i := 0; i < 28; i++ {
				name := fmt.Sprintf("Peripheral %02d", i)
				if i == 27 {
					name = "Literal %_ search"
				}
				var err error
				if kind == inventory.MonitorReports {
					err = f.client.Monitor.Create().SetModel(name).SetManufacturer("Example Displays").SetSerial("Serial-AB").SetWeekOfManufacture("07").SetYearOfManufacture("2024").SetOwnerID(f.id).Exec(t.Context())
				} else {
					err = f.client.Printer.Create().SetName(name).SetPort("IP_192.0.2.15").SetIsDefault(true).SetIsNetwork(false).SetIsShared(true).SetOwnerID(f.id).Exec(t.Context())
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			read := func(search string, after int64) *inventory.PeripheralsPage {
				t.Helper()
				page, err := inventory.ReadPeripherals(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.PeripheralsFilter{Kind: kind, ReportFilter: inventory.ReportFilter{Search: search, After: after}})
				if err != nil {
					t.Fatal(err)
				}
				return page
			}
			first := read("", 0)
			if len(first.Entries) != 25 || first.Next == 0 || first.DeviceID != f.id || first.SiteID != f.scope.SiteID {
				t.Fatal("first page or scope incorrect", first)
			}
			second := read("", first.Next)
			if len(second.Entries) != 3 || second.Next != 0 || second.Entries[0].ID <= first.Next {
				t.Fatal("keyset page repeated or skipped entries", second)
			}
			if got := read("%_", 0); len(got.Entries) != 1 || got.Entries[0].Name != "Literal %_ search" {
				t.Fatal("search interpreted wildcards", got)
			}
			if got := read("pErIpHeRaL 01", 0); len(got.Entries) != 1 || got.Entries[0].Name != "Peripheral 01" {
				t.Fatal("name search failed", got)
			}
			searches := []string{"dIsPlAyS", "sErIaL-ab"}
			if kind == inventory.PrinterReports {
				searches = []string{"ip_", "192.0.2.15"}
			}
			for _, search := range searches {
				if got := read(search, 0); len(got.Entries) != 25 || got.Next == 0 {
					t.Fatal("case insensitive search not bounded", got)
				}
			}
			if got := read("' OR true --", 0); len(got.Entries) != 0 || got.DeviceID != f.id {
				t.Fatal("literal search changed scope", got)
			}
			if got := read("", 9223372036854775807); len(got.Entries) != 0 || got.Next != 0 {
				t.Fatal("empty final page incorrect", got)
			}
			item := first.Entries[0]
			if kind == inventory.MonitorReports {
				if item.Manufacturer != "Example Displays" || item.Serial != "Serial-AB" || item.Week != "07" || item.Year != "2024" || item.Port != "" || item.Default != nil || item.Network != nil || item.Shared != nil {
					t.Fatal("monitor projection changed", item)
				}
			} else if item.Port != "IP_192.0.2.15" || item.Default == nil || !*item.Default || item.Network == nil || *item.Network || item.Shared == nil || !*item.Shared || item.Manufacturer != "" || item.Serial != "" || item.Week != "" || item.Year != "" {
				t.Fatal("printer projection changed", item)
			}
			var count int
			if err := f.db.QueryRow(`SELECT count(*) FROM uem_inventory_audit WHERE actor='viewer' AND tenant_id=$1 AND site_id=$2 AND action='inventory.peripherals.read' AND resource_id=$3`, f.scope.TenantID, f.scope.SiteID, f.id).Scan(&count); err != nil || count != 8 {
				t.Fatal("peripherals reads not scoped and audited", count, err)
			}
			if err := f.client.Agent.UpdateOneID(f.id).ClearSite().AddSiteIDs(f.otherSite).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
			if got, err := inventory.ReadPeripherals(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.PeripheralsFilter{Kind: kind, ReportFilter: inventory.ReportFilter{After: first.Next}}); got != nil || !errors.Is(err, inventory.ErrNotFound) {
				t.Fatal("cursor preserved access after move", got, err)
			}
		})
	}
}

func TestPeripheralsInventoryRejectsHiddenObjectsRevokedReadsAndAuditFailure(t *testing.T) {
	for _, kind := range []inventory.PeripheralsKind{inventory.MonitorReports, inventory.PrinterReports} {
		t.Run(string(kind), func(t *testing.T) {
			f := newSoftwareFixture(t)
			read := func() (*inventory.PeripheralsPage, error) {
				return inventory.ReadPeripherals(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.PeripheralsFilter{Kind: kind})
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
			if _, err := f.db.Exec(`ALTER TABLE uem_inventory_audit ADD CONSTRAINT peripherals_audit_failure CHECK(action<>'inventory.peripherals.read') NOT VALID`); err != nil {
				t.Fatal(err)
			}
			if got, err := read(); got != nil || err == nil {
				t.Fatal("audit failure returned data", got, err)
			}
			if _, err := f.db.Exec(`ALTER TABLE uem_inventory_audit DROP CONSTRAINT peripherals_audit_failure`); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if got, err := inventory.ReadPeripherals(ctx, f.db, f.permissions, "viewer", f.scope, f.id, inventory.PeripheralsFilter{Kind: kind}); got != nil || !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled read continued", got, err)
			}
			for _, filter := range []inventory.PeripheralsFilter{{Kind: ""}, {Kind: "MONITORS"}, {Kind: "monitors;SELECT"}, {Kind: kind, ReportFilter: inventory.ReportFilter{After: -1}}, {Kind: kind, ReportFilter: inventory.ReportFilter{Search: strings.Repeat("x", 257)}}, {Kind: kind, ReportFilter: inventory.ReportFilter{Search: "line\nbreak"}}, {Kind: kind, ReportFilter: inventory.ReportFilter{Search: string([]byte{0xff})}}} {
				if got, err := inventory.ReadPeripherals(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, filter); got != nil || !errors.Is(err, inventory.ErrPeripheralsFilter) {
					t.Fatal("invalid peripherals filter accepted", got, err)
				}
			}
			if err := f.permissions.ReplaceGrants(t.Context(), "admin", "viewer", 1, nil); err != nil {
				t.Fatal(err)
			}
			if got, err := read(); got != nil || !errors.Is(err, access.ErrDenied) {
				t.Fatal("revoked viewer retained peripherals access", got, err)
			}
		})
	}
}

func TestPeripheralsInventoryLargeForeignReportsAndAbsentFlags(t *testing.T) {
	f := newSoftwareFixture(t)
	if err := f.client.Agent.Create().SetID("large-hidden-peripherals").SetHostname("Hidden peripherals").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.otherSite).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []inventory.PeripheralsKind{inventory.MonitorReports, inventory.PrinterReports} {
		var statement, index, owner string
		if kind == inventory.MonitorReports {
			statement = `INSERT INTO monitors(model,agent_monitors) SELECT 'Peripheral '||n,$1 FROM generate_series(1,$2) n`
			index, owner = "uem_inventory_monitor_cursor", "agent_monitors"
		} else {
			statement = `INSERT INTO printers(name,agent_printers) SELECT 'Peripheral '||n,$1 FROM generate_series(1,$2) n`
			index, owner = "uem_inventory_printer_cursor", "agent_printers"
		}
		for _, seed := range []struct {
			id    string
			count int
		}{{"large-hidden-peripherals", 50000}, {f.id, 30}} {
			if _, err := f.db.Exec(statement, seed.id, seed.count); err != nil {
				t.Fatal(err)
			}
		}
		page, err := inventory.ReadPeripherals(t.Context(), f.db, f.permissions, "operator", f.scope, f.id, inventory.PeripheralsFilter{Kind: kind})
		if err != nil || page == nil || len(page.Entries) != 25 || page.Next == 0 {
			t.Fatal("large foreign report blocked bounded inventory", page, err)
		}
		for i, item := range page.Entries {
			if item.Name != fmt.Sprintf("Peripheral %d", i+1) || item.ID <= 50000 || item.Manufacturer != "" || item.Serial != "" || item.Week != "" || item.Year != "" || item.Port != "" || item.Default != nil || item.Network != nil || item.Shared != nil {
				t.Fatal("foreign or invented peripheral report data", item)
			}
		}
		page, err = inventory.ReadPeripherals(t.Context(), f.db, f.permissions, "operator", f.scope, f.id, inventory.PeripheralsFilter{Kind: kind, ReportFilter: inventory.ReportFilter{After: page.Next}})
		if err != nil || page == nil || len(page.Entries) != 5 || page.Next != 0 {
			t.Fatal("large peripherals continuation failed", page, err)
		}
		var definition string
		if err := f.db.QueryRow(`SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname=$1`, index).Scan(&definition); err != nil || !strings.Contains(definition, "("+owner+", id)") {
			t.Fatal("peripherals cursor index missing", definition, err)
		}
	}
}
