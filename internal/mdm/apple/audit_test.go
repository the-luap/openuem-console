package apple

import (
	"encoding/json"
	"strings"
	"testing"

	"howett.net/plist"
)

func TestAuditCapturesOriginalSiteAndExplicitCommandOutcomes(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	d, _ := testEnroll(t, s, Scope{TenantID: 1, SiteID: 1}, "Audit phone")
	if _, err := s.db.Exec(`INSERT INTO sites(id,tenant_sites) VALUES(3,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE mdm_apple_devices SET site_id=3 WHERE id=$1`, d.ID); err != nil {
		t.Fatal(err)
	}
	payload, err := s.Connect(t.Context(), d, map[string]any{"UDID": d.UDID, "Status": "Idle"})
	if err != nil {
		t.Fatal(err)
	}
	var command map[string]any
	if _, err = plist.Unmarshal(payload, &command); err != nil {
		t.Fatal(err)
	}
	id := command["CommandUUID"].(string)
	if _, err = s.Connect(t.Context(), d, map[string]any{"UDID": d.UDID, "Status": "NotNow", "CommandUUID": id}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_commands SET available_at=now()-interval '1 minute' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Connect(t.Context(), d, map[string]any{"UDID": d.UDID, "Status": "Idle"}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Connect(t.Context(), d, map[string]any{"UDID": d.UDID, "Status": "Error", "CommandUUID": id, "ErrorChain": []any{map[string]any{"LocalizedDescription": "private command error must stay outside audit"}}}); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		action, resource, result string
		site                     int
	}{{"apple.enrollment.invite", d.ID, "success", 1}, {"apple.command.not_now", id, "deferred", 3}, {"apple.command.failed", id, "failure", 3}} {
		var raw []byte
		if err = s.db.QueryRow(`SELECT details FROM mdm_apple_audit WHERE action=$1 AND resource_id=$2 ORDER BY id DESC LIMIT 1`, entry.action, entry.resource).Scan(&raw); err != nil {
			t.Fatal(entry.action, err)
		}
		var details struct {
			Site   int    `json:"site_id"`
			Result string `json:"result"`
		}
		if json.Unmarshal(raw, &details) != nil || details.Site != entry.site || details.Result != entry.result || strings.Contains(string(raw), "private command error") {
			t.Fatal("audit lost original scope or result", entry, string(raw))
		}
	}
}
