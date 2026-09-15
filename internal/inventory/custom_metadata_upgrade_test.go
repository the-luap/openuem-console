package inventory_test

import (
	"database/sql"
	"testing"

	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestCustomMetadataUpgradePreservesLegacyValuesAndUnrelatedIndexes(t *testing.T) {
	field := 0
	f := newRefreshFixtureBeforeMigration(t, nil, func(db *sql.DB, client *ent.Client, id string, scope access.Scope) {
		definition, err := client.OrgMetadata.Create().SetName("Legacy shared field").SetDescription("Retained legacy help").SetTenantID(scope.TenantID).Save(t.Context())
		require.NoError(t, err)
		field = definition.ID
		require.NoError(t, client.Metadata.Create().SetOwnerID(id).SetOrgID(field).SetValue("Retained legacy value").Exec(t.Context()))
		// Both forms of the old global invariant must be removed, without dropping
		// unrelated native indexes or the existing values they protect.
		_, err = db.ExecContext(t.Context(), `CREATE UNIQUE INDEX legacy_global_field_name ON org_metadata(name)`)
		require.NoError(t, err)
		_, err = db.ExecContext(t.Context(), `CREATE INDEX retained_metadata_help ON org_metadata(description)`)
		require.NoError(t, err)
	})
	var value, revision, fieldRevision string
	var changed bool
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT m.value,r.revision::text,r.changed,f.uem_revision::text FROM metadata m JOIN org_metadata f ON f.id=m.org_metadata_metadata JOIN uem_metadata_value_revisions r ON r.device_id=m.agent_metadata AND r.field_id=f.id WHERE f.id=$1`, field).Scan(&value, &revision, &changed, &fieldRevision))
	require.Equal(t, "Retained legacy value", value)
	require.True(t, changed)
	require.NotEmpty(t, revision)
	require.NotEmpty(t, fieldRevision)
	var count int
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM pg_indexes WHERE schemaname=current_schema() AND indexname='retained_metadata_help'`).Scan(&count))
	require.Equal(t, 1, count)
	other, err := f.client.Tenant.Create().SetDescription("Second organization").Save(t.Context())
	require.NoError(t, err)
	require.NoError(t, f.client.OrgMetadata.Create().SetName("Legacy shared field").SetTenantID(other.ID).Exec(t.Context()))
	require.Error(t, f.client.OrgMetadata.Create().SetName("Legacy shared field").SetTenantID(f.scope.TenantID).Exec(t.Context()))
	require.NoError(t, f.store.Migrate(t.Context()))
}

func TestCustomMetadataStartupRejectsMissingOrGlobalNameIndexes(t *testing.T) {
	for _, statement := range []string{
		`DROP INDEX uem_metadata_field_name_tenant`,
		`CREATE UNIQUE INDEX legacy_global_name ON org_metadata(name)`,
		`ALTER TABLE metadata DISABLE TRIGGER uem_metadata_value_revision`,
		`ALTER TABLE org_metadata DISABLE TRIGGER uem_metadata_field_revision`,
		`ALTER TABLE uem_metadata_value_revisions DISABLE TRIGGER uem_metadata_value_revision_guard`,
		`ALTER TABLE uem_metadata_field_deletions DISABLE TRIGGER uem_metadata_field_deletion_guard`,
	} {
		t.Run(statement, func(t *testing.T) {
			f := newRefreshFixture(t, nil)
			_, err := f.db.ExecContext(t.Context(), statement)
			require.NoError(t, err)
			require.Error(t, f.store.Migrate(t.Context()))
		})
	}
}
