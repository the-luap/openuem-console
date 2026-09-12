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

func TestNetworkInventoryPagesSearchAndAudit(t *testing.T) {
	f := newSoftwareFixture(t)
	for i := 0; i < 27; i++ {
		if err := f.client.NetworkAdapter.Create().SetName(fmt.Sprintf("Adapter %02d", i)).SetMACAddress("AA:BB:CC:DD:EE:FF").SetAddresses("2001:DB8::1").SetSpeed("1 Gbps").SetSubnet("/64").SetDefaultGateway("2001:db8::ff").SetDNSServers("2001:db8::53").SetDNSDomain("Example.test").SetDhcpEnabled(true).SetVirtual(false).SetOwnerID(f.id).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.client.NetworkAdapter.Create().SetName("Literal %_ search").SetMACAddress("00:11:22:33:44:55").SetAddresses("192.0.2.1").SetSpeed("Not reported").SetOwnerID(f.id).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	read := func(filter inventory.NetworkFilter) *inventory.NetworkPage {
		t.Helper()
		page, err := inventory.ReadNetwork(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, filter)
		if err != nil {
			t.Fatal(err)
		}
		return page
	}
	first := read(inventory.NetworkFilter{})
	if len(first.Entries) != 25 || first.Next == 0 || first.DeviceID != f.id || first.SiteID != f.scope.SiteID {
		t.Fatal("first page or scope incorrect", first)
	}
	second := read(inventory.NetworkFilter{After: first.Next})
	if len(second.Entries) != 3 || second.Next != 0 || second.Entries[0].ID <= first.Next {
		t.Fatal("keyset page repeated or skipped entries", second)
	}
	if got := read(inventory.NetworkFilter{Search: "%_"}); len(got.Entries) != 1 || got.Entries[0].Name != "Literal %_ search" {
		t.Fatal("search interpreted SQL wildcards", got)
	}
	if got := read(inventory.NetworkFilter{Search: "aA:Bb"}); len(got.Entries) != 25 || got.Next == 0 {
		t.Fatal("MAC search is not bounded or case insensitive", got)
	}
	if got := read(inventory.NetworkFilter{Search: "' OR true --"}); len(got.Entries) != 0 || got.DeviceID != f.id {
		t.Fatal("literal search changed scope", got)
	}
	if got := read(inventory.NetworkFilter{After: 9223372036854775807}); len(got.Entries) != 0 || got.Next != 0 {
		t.Fatal("empty final page incorrect", got)
	}
	if got := read(inventory.NetworkFilter{Search: "aDaPtEr 01"}); len(got.Entries) != 1 || got.Entries[0].Name != "Adapter 01" {
		t.Fatal("adapter name search failed", got)
	}
	if got := read(inventory.NetworkFilter{Search: "2001:db8"}); len(got.Entries) != 25 || got.Next == 0 {
		t.Fatal("IPv6 search is not bounded or case insensitive", got)
	}
	item := first.Entries[0]
	if item.MAC != "AA:BB:CC:DD:EE:FF" || item.Addresses != "2001:DB8::1" || item.Subnet != "/64" || item.Gateway != "2001:db8::ff" || item.DNS != "2001:db8::53" || item.Domain != "Example.test" || item.Speed != "1 Gbps" || item.DHCPEnabled == nil || !*item.DHCPEnabled || item.Virtual == nil || *item.Virtual {
		t.Fatal("reported adapter projection changed", item)
	}
	var count int
	if err := f.db.QueryRow(`SELECT count(*) FROM uem_inventory_audit WHERE actor='viewer' AND tenant_id=$1 AND site_id=$2 AND action='inventory.network.read' AND resource_id=$3`, f.scope.TenantID, f.scope.SiteID, f.id).Scan(&count); err != nil || count != 8 {
		t.Fatal("network reads were not scoped and audited", count, err)
	}
	if err := f.client.Agent.UpdateOneID(f.id).ClearSite().AddSiteIDs(f.otherSite).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, err := inventory.ReadNetwork(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.NetworkFilter{After: first.Next}); got != nil || !errors.Is(err, inventory.ErrNotFound) {
		t.Fatal("cursor preserved access after a move", got, err)
	}
}

func TestNetworkInventoryRejectsHiddenObjectsAndRevokedReads(t *testing.T) {
	f := newSoftwareFixture(t)
	read := func() (*inventory.NetworkPage, error) {
		return inventory.ReadNetwork(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.NetworkFilter{})
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
	if _, err := f.db.Exec(`ALTER TABLE uem_inventory_audit ADD CONSTRAINT network_audit_failure CHECK(action<>'inventory.network.read') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if got, err := read(); got != nil || err == nil {
		t.Fatal("audit failure returned report data", got, err)
	}
	if _, err := f.db.Exec(`ALTER TABLE uem_inventory_audit DROP CONSTRAINT network_audit_failure`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := inventory.ReadNetwork(ctx, f.db, f.permissions, "viewer", f.scope, f.id, inventory.NetworkFilter{}); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read continued", got, err)
	}
	for _, filter := range []inventory.NetworkFilter{{After: -1}, {Search: strings.Repeat("x", 257)}, {Search: "line\nbreak"}, {Search: string([]byte{0xff})}} {
		if got, err := inventory.ReadNetwork(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, filter); got != nil || !errors.Is(err, inventory.ErrNetworkFilter) {
			t.Fatal("invalid filter accepted", got, err)
		}
	}
	if err := f.permissions.ReplaceGrants(t.Context(), "admin", "viewer", 1, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := read(); got != nil || !errors.Is(err, access.ErrDenied) {
		t.Fatal("revoked viewer retained network access", got, err)
	}
}

func TestNetworkInventoryWithLargeForeignReport(t *testing.T) {
	f := newSoftwareFixture(t)
	if err := f.client.Agent.Create().SetID("large-hidden-report").SetHostname("Hidden report").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.otherSite).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO network_adapters(name,mac_address,addresses,speed,agent_networkadapters) SELECT 'Hidden adapter '||n,'00:11:22:33:44:55','192.0.2.2','1 Gbps','large-hidden-report' FROM generate_series(1,50000) n`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO network_adapters(name,mac_address,addresses,speed,agent_networkadapters) SELECT 'Visible adapter '||n,'AA:BB:CC:DD:EE:FF','192.0.2.1','1 Gbps',$1 FROM generate_series(1,30) n`, f.id); err != nil {
		t.Fatal(err)
	}
	page, err := inventory.ReadNetwork(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.NetworkFilter{})
	if err != nil || page == nil || len(page.Entries) != 25 || page.Next == 0 {
		t.Fatal("large foreign report blocked bounded inventory", page, err)
	}
	for _, item := range page.Entries {
		if !strings.HasPrefix(item.Name, "Visible adapter ") {
			t.Fatal("foreign adapter entered page", item)
		}
	}
	page, err = inventory.ReadNetwork(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id, inventory.NetworkFilter{After: page.Next})
	if err != nil || page == nil || len(page.Entries) != 5 || page.Next != 0 {
		t.Fatal("large inventory continuation failed", page, err)
	}
}

func TestNetworkInventoryPreservesAbsentFlags(t *testing.T) {
	f := newSoftwareFixture(t)
	if _, err := f.db.Exec(`INSERT INTO network_adapters(name,mac_address,addresses,speed,dhcp_enabled,virtual,agent_networkadapters) VALUES('Absent flags','','','',NULL,NULL,$1),('Present flags','','','',false,true,$1)`, f.id); err != nil {
		t.Fatal(err)
	}
	page, err := inventory.ReadNetwork(t.Context(), f.db, f.permissions, "operator", f.scope, f.id, inventory.NetworkFilter{})
	if err != nil || page == nil || len(page.Entries) != 2 {
		t.Fatal("operator report unavailable", page, err)
	}
	absent, present := page.Entries[0], page.Entries[1]
	if absent.DHCPEnabled != nil || absent.Virtual != nil || present.DHCPEnabled == nil || *present.DHCPEnabled || present.Virtual == nil || !*present.Virtual {
		t.Fatal("missing and reported flags conflated", absent, present)
	}
	var index string
	if err := f.db.QueryRow(`SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname='uem_inventory_network_cursor'`).Scan(&index); err != nil || !strings.Contains(index, "(agent_networkadapters, id)") {
		t.Fatal("network cursor index missing", index, err)
	}
}
