package audit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestCustomMetadataAuditOrganizationAndDeviceScopeRetention(t *testing.T) {
	s := testStore(t, false)
	actions := []string{"fields.list", "field.read", "field.create", "field.update", "field.delete_review", "field.delete", "field.receipt", "values.list", "value.read", "value.update", "value.clear"}
	for i, action := range actions {
		site := 0
		if i >= 7 {
			site = 11
		}
		_, err := s.db.ExecContext(t.Context(), `INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id,created_at) VALUES(1,$1,'reader',$2,$3,clock_timestamp()-interval '45 days'),(2,21,'reader',$2,$3,clock_timestamp()-interval '45 days')`, site, "inventory.metadata."+action, "metadata-"+action)
		require.NoError(t, err)
	}
	for _, site := range []int{0, 11} {
		filter := Filter{Scope: access.Scope{TenantID: 1, SiteID: site}, Source: "inventory", From: time.Now().AddDate(0, 0, -60), Until: time.Now().Add(time.Minute)}
		data, err := s.ExportJSON(t.Context(), "organization-admin", filter)
		require.NoError(t, err)
		var events []Event
		require.NoError(t, json.Unmarshal(data, &events))
		expected := 11
		if site > 0 {
			expected = 4
		}
		require.Len(t, events, expected)
		for _, event := range events {
			require.Equal(t, 1, event.TenantID)
			if site > 0 {
				require.Equal(t, 11, event.SiteID)
			}
		}
	}
	scope := access.Scope{TenantID: 1}
	preview, err := s.PreviewRetention(t.Context(), "organization-admin", scope, 30)
	require.NoError(t, err)
	require.EqualValues(t, 11, preview.Counts["inventory"])
	require.NoError(t, s.ApplyRetention(t.Context(), "organization-admin", scope, preview.ID, preview.Token))
	require.NoError(t, s.PruneRetention(t.Context()))
	var count int
	require.NoError(t, s.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_inventory_audit WHERE tenant_id=1 AND action LIKE 'inventory.metadata.%'`).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, s.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_inventory_audit WHERE tenant_id=2 AND action LIKE 'inventory.metadata.%'`).Scan(&count))
	require.Equal(t, 11, count)
}
