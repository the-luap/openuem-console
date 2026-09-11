package audit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestInventoryAuditScopeExportAndRetentionWithoutEnrollment(t *testing.T) {
	s := testStore(t, false)
	if _, err := s.db.Exec(`INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id,created_at) VALUES
 (1,11,'reader','inventory.desktop.read','legacy-old',clock_timestamp()-interval '45 days'),
 (1,11,'reader','inventory.network.read','network-old',clock_timestamp()-interval '45 days'),
 (1,11,'reader','inventory.software.read','software-old',clock_timestamp()-interval '45 days'),
 (1,12,'reader','inventory.desktop.read','legacy-recent',clock_timestamp()),
 (2,21,'reader','inventory.desktop.read','legacy-foreign',clock_timestamp()-interval '45 days')`); err != nil {
		t.Fatal(err)
	}
	f := Filter{Scope: access.Scope{TenantID: 1, SiteID: 11}, Source: "inventory", From: time.Now().AddDate(0, 0, -60), Until: time.Now().Add(time.Minute)}
	data, err := s.ExportJSON(t.Context(), "organization-admin", f)
	if err != nil {
		t.Fatal(err)
	}
	var events []Event
	if err = json.Unmarshal(data, &events); err != nil || len(events) != 3 {
		t.Fatal("inventory export lost historical scope", string(data), err)
	}
	want := map[string]string{"legacy-old": "inventory.desktop.read", "network-old": "inventory.network.read", "software-old": "inventory.software.read"}
	for _, event := range events {
		if event.SiteID != 11 || want[event.Resource] != event.Action {
			t.Fatal("inventory export lost source action or scope", event)
		}
		delete(want, event.Resource)
	}
	if len(want) != 0 {
		t.Fatal("inventory source missing from export", want)
	}
	scope := access.Scope{TenantID: 1}
	preview, err := s.PreviewRetention(t.Context(), "organization-admin", scope, 30)
	if err != nil || preview.Counts["inventory"] != 3 {
		t.Fatal("inventory retention preview is not scoped", preview, err)
	}
	if err = s.ApplyRetention(t.Context(), "organization-admin", scope, preview.ID, preview.Token); err != nil {
		t.Fatal(err)
	}
	if err = s.PruneRetention(t.Context()); err != nil {
		t.Fatal(err)
	}
	var remaining, history int
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_inventory_audit WHERE resource_id IN ('legacy-recent','legacy-foreign')`).Scan(&remaining); err != nil || remaining != 2 {
		t.Fatal("retention erased foreign or recent inventory evidence", remaining, err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM uem_inventory_audit WHERE resource_id IN ('legacy-old','network-old','software-old')`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatal("confirmed inventory retention was not applied", remaining, err)
	}
	if err = s.db.QueryRow(`SELECT sum(event_count) FROM uem_audit_retention_history WHERE tenant_id=1 AND source='inventory'`).Scan(&history); err != nil || history != 3 {
		t.Fatal("inventory erasure receipt missing", history, err)
	}
}
