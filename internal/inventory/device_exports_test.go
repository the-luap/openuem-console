package inventory_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/ent"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestDeviceExportsPreserveScopeValuesAndCommittedAudit(t *testing.T) {
	f := newSoftwareFixture(t)
	ctx := t.Context()
	name := "\u200b=HYPERLINK(\"https://owned.invalid\",\"owned\")"
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetNickname(name).SetLastContact(time.Date(2026, 9, 1, 12, 0, 0, 123456000, time.FixedZone("Owned offset", 7200))).Exec(ctx))
	require.NoError(t, f.client.Agent.Create().SetID("foreign-export").SetHostname("Foreign export canary").SetOs("linux").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.otherSite).Exec(ctx))
	for i := range 30 {
		require.NoError(t, f.client.Agent.Create().SetID(fmt.Sprintf("export-%02d", i)).SetHostname(fmt.Sprintf("Export %02d", i)).SetOs("linux").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(ctx))
	}
	read := func(format string, filter inventory.DeviceFilter) []byte {
		t.Helper()
		data, err := inventory.ExportDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, filter, format)
		require.NoError(t, err)
		require.NotContains(t, string(data), "Foreign export canary")
		return data
	}
	data := read("json", inventory.DeviceFilter{Sort: "name_desc"})
	var rows []map[string]any
	require.NoError(t, json.Unmarshal(data, &rows))
	require.Len(t, rows, 31, "export stopped at the visible page")
	for _, row := range rows {
		require.Len(t, row, 12, "the export projection gained unexpected fields")
		require.Equal(t, float64(f.scope.TenantID), row["organization_id"])
		require.Equal(t, float64(f.scope.SiteID), row["site_id"])
		if row["device_id"] == f.id {
			require.Equal(t, name, row["name"], "JSON changed the original name")
			require.Equal(t, "2026-09-01T10:00:00.123456Z", row["last_contact"])
		} else {
			require.Nil(t, row["last_contact"], "missing contact became an invented instant")
		}
	}
	csvRows, err := csv.NewReader(bytes.NewReader(read("csv", inventory.DeviceFilter{}))).ReadAll()
	require.NoError(t, err)
	require.Len(t, csvRows, 32)
	require.Equal(t, "Last contact (UTC)", csvRows[0][11])
	for _, row := range csvRows[1:] {
		if row[1] == f.id {
			require.Equal(t, "[text] "+name, row[4])
			require.Equal(t, "2026-09-01T10:00:00.123456Z", row[11])
		}
	}
	require.NoError(t, json.Unmarshal(read("json", inventory.DeviceFilter{Search: "Export", Sort: "name_desc"}), &rows))
	require.Len(t, rows, 30)
	require.Equal(t, "Export 29", rows[0]["name"])
	require.Equal(t, "[]", string(read("json", inventory.DeviceFilter{Search: "no matching device"})))
	var count int
	require.NoError(t, f.db.QueryRow(`SELECT count(*) FROM uem_inventory_audit WHERE tenant_id=$1 AND site_id=$2 AND actor='viewer' AND action IN ('inventory.devices.export_csv','inventory.devices.export_json')`, f.scope.TenantID, f.scope.SiteID).Scan(&count))
	require.Equal(t, 4, count)
	_, err = f.db.Exec(`ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_export_failure CHECK(action NOT IN ('inventory.devices.export_csv','inventory.devices.export_json')) NOT VALID`)
	require.NoError(t, err)
	data, err = inventory.ExportDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, inventory.DeviceFilter{}, "json")
	require.Error(t, err)
	require.Nil(t, data, "prepared export escaped after its audit failed")
	_, err = f.db.Exec(`ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_export_failure`)
	require.NoError(t, err)
	for _, format := range []string{"xml", "../csv"} {
		data, err = inventory.ExportDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, inventory.DeviceFilter{}, format)
		require.ErrorIs(t, err, inventory.ErrReportFilter)
		require.Nil(t, data)
	}
	data, err = inventory.ExportDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, inventory.DeviceFilter{After: "owned-position"}, "csv")
	require.ErrorIs(t, err, inventory.ErrReportFilter)
	require.Nil(t, data)
	data, err = inventory.ExportDevices(ctx, f.db, f.permissions, "viewer", access.Scope{TenantID: f.scope.TenantID}, inventory.DeviceSources{}, inventory.DeviceFilter{}, "json")
	require.ErrorIs(t, err, access.ErrDenied)
	require.Nil(t, data)
	_, err = inventory.ExportDevices(ctx, f.db, f.permissions, "admin", access.Scope{TenantID: f.scope.TenantID}, inventory.DeviceSources{}, inventory.DeviceFilter{}, "json")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "viewer", 1, nil))
	data, err = inventory.ExportDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, inventory.DeviceFilter{}, "json")
	require.ErrorIs(t, err, access.ErrDenied)
	require.Nil(t, data)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	data, err = inventory.ExportDevices(cancelled, f.db, f.permissions, "admin", f.scope, inventory.DeviceSources{}, inventory.DeviceFilter{}, "json")
	require.Error(t, err)
	require.Nil(t, data)
}

func TestDeviceExportRejectsOversizedMetadataAndExcessRows(t *testing.T) {
	f := newSoftwareFixture(t)
	ctx := t.Context()
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetNickname(strings.Repeat("x", 4097)).Exec(ctx))
	for _, format := range []string{"json", "csv"} {
		data, err := inventory.ExportDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, inventory.DeviceFilter{}, format)
		require.ErrorIs(t, err, inventory.ErrDeviceExportTooLarge)
		require.Nil(t, data)
	}
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetNickname("Visible original device").Exec(ctx))
	for batch := range 50 {
		builders := make([]*ent.AgentCreate, 100)
		for i := range builders {
			builders[i] = f.client.Agent.Create().SetID(fmt.Sprintf("large-export-%d-%d", batch, i)).SetHostname("Large export fixture").SetOs("linux").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID)
		}
		require.NoError(t, f.client.Agent.CreateBulk(builders...).Exec(ctx))
	}
	data, err := inventory.ExportDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, inventory.DeviceFilter{}, "json")
	require.ErrorIs(t, err, inventory.ErrDeviceExportTooLarge)
	require.Nil(t, data)
	data, err = inventory.ExportDevices(ctx, f.db, f.permissions, "viewer", f.scope, inventory.DeviceSources{}, inventory.DeviceFilter{Platform: "linux"}, "json")
	require.NoError(t, err, "exactly 5,000 matching devices must be exportable")
	var rows []map[string]any
	require.NoError(t, json.Unmarshal(data, &rows))
	require.Len(t, rows, 5000)
}
