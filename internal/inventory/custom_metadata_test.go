package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

type metadataFixture struct {
	*refreshFixture
	field *inventory.MetadataField
}

func newMetadataFixture(t *testing.T) *metadataFixture {
	t.Helper()
	f := newSoftwareFixture(t)
	require.NoError(t, f.client.User.Create().SetID("metadata-admin").SetName("Metadata administrator").SetEmail("metadata@example.test").SetUse2fa(false).Exec(t.Context()))
	require.NoError(t, f.permissions.ReplaceGrants(t.Context(), "admin", "metadata-admin", 0, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: f.scope.TenantID}}}))
	field, err := inventory.SaveMetadataField(t.Context(), f.db, f.permissions, "metadata-admin", f.scope.TenantID, 0, "", "Owner's field <script>", "Private help\nSecond line")
	require.NoError(t, err)
	return &metadataFixture{f, field}
}
func (f *metadataFixture) read(t *testing.T) *inventory.MetadataValue {
	t.Helper()
	v, err := inventory.ReadMetadataValue(t.Context(), f.db, f.permissions, "metadata-admin", f.scope, f.id, f.field.ID)
	require.NoError(t, err)
	return v
}
func (f *metadataFixture) save(t *testing.T, v *inventory.MetadataValue, value string, clear bool) *inventory.MetadataValue {
	t.Helper()
	out, err := inventory.SaveMetadataValue(t.Context(), f.db, f.permissions, "metadata-admin", f.scope, f.id, f.field.ID, v.Field.Revision, v.Revision, value, clear)
	require.NoError(t, err)
	return out
}
func (f *metadataFixture) review(t *testing.T) *inventory.MetadataDeletion {
	t.Helper()
	r, err := inventory.ReviewMetadataDeletion(t.Context(), f.db, f.permissions, "metadata-admin", f.scope.TenantID, f.field.ID, f.field.Revision)
	require.NoError(t, err)
	return r
}

func TestCustomMetadataScopedNamesPaginationAndDefinitionRevisions(t *testing.T) {
	f := newMetadataFixture(t)
	ctx := t.Context()
	other, err := f.client.Tenant.Create().SetDescription("Foreign organization").Save(ctx)
	require.NoError(t, err)
	_, err = inventory.SaveMetadataField(ctx, f.db, f.permissions, "admin", other.ID, 0, "", f.field.Name, "Foreign definition")
	require.NoError(t, err)
	_, err = inventory.SaveMetadataField(ctx, f.db, f.permissions, "admin", f.scope.TenantID, 0, "", f.field.Name, "Duplicate")
	require.ErrorIs(t, err, inventory.ErrMetadataNameUnavailable)
	for n := range 53 {
		_, err = inventory.SaveMetadataField(ctx, f.db, f.permissions, "admin", f.scope.TenantID, 0, "", fmt.Sprintf("Literal %%_\\ field %02d", n), "Help")
		require.NoError(t, err)
	}
	total, after := 0, 0
	for {
		page, err := inventory.ListMetadataFields(ctx, f.db, f.permissions, "metadata-admin", f.scope.TenantID, "%_\\", after)
		require.NoError(t, err)
		require.LessOrEqual(t, len(page.Fields), 25)
		for _, field := range page.Fields {
			require.Equal(t, f.scope.TenantID, field.TenantID)
			require.Greater(t, field.ID, after)
		}
		total += len(page.Fields)
		if page.Next == 0 {
			break
		}
		after = page.Next
	}
	require.Equal(t, 53, total)
	first := f.field
	updated, err := inventory.SaveMetadataField(ctx, f.db, f.permissions, "metadata-admin", f.scope.TenantID, first.ID, first.Revision, "New name", "New description")
	require.NoError(t, err)
	require.NotEqual(t, first.Revision, updated.Revision)
	_, err = inventory.SaveMetadataField(ctx, f.db, f.permissions, "metadata-admin", f.scope.TenantID, first.ID, first.Revision, "Stale", "Stale")
	require.ErrorIs(t, err, inventory.ErrMetadataConflict)
	require.NoError(t, f.client.OrgMetadata.UpdateOneID(first.ID).SetName("Away").Exec(ctx))
	require.NoError(t, f.client.OrgMetadata.UpdateOneID(first.ID).SetName(updated.Name).Exec(ctx))
	latest, err := inventory.ReadMetadataField(ctx, f.db, f.permissions, "admin", f.scope.TenantID, first.ID)
	require.NoError(t, err)
	require.NotEqual(t, updated.Revision, latest.Revision)
	_, err = f.db.ExecContext(ctx, `UPDATE org_metadata SET uem_revision=$2 WHERE id=$1`, first.ID, uuid.NewString())
	require.Error(t, err)
	require.NoError(t, f.client.OrgMetadata.UpdateOneID(first.ID).SetTenantID(other.ID).Exec(ctx))
	_, err = inventory.ReadMetadataField(ctx, f.db, f.permissions, "admin", f.scope.TenantID, first.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	moved, err := inventory.ReadMetadataField(ctx, f.db, f.permissions, "admin", other.ID, first.ID)
	require.NoError(t, err)
	require.NotEqual(t, latest.Revision, moved.Revision)
}

func TestCustomMetadataValueRevisionsAbsenceAndConcurrentWriters(t *testing.T) {
	f := newMetadataFixture(t)
	ctx := t.Context()
	first := f.read(t)
	require.False(t, first.Present)
	require.Equal(t, first.Revision, f.read(t).Revision)
	empty := f.save(t, first, "", false)
	require.True(t, empty.Present)
	require.NotEqual(t, first.Revision, empty.Revision)
	require.Equal(t, empty.Revision, f.save(t, empty, "", false).Revision)
	absent := f.save(t, empty, "", true)
	require.False(t, absent.Present)
	require.NotEqual(t, empty.Revision, absent.Revision)
	require.NoError(t, f.client.Metadata.Create().SetOwnerID(f.id).SetOrgID(f.field.ID).SetValue("Legacy value").Exec(ctx))
	_, err := f.db.ExecContext(ctx, `DELETE FROM metadata WHERE agent_metadata=$1`, f.id)
	require.NoError(t, err)
	latest := f.read(t)
	require.False(t, latest.Present)
	require.NotEqual(t, absent.Revision, latest.Revision)
	_, err = inventory.SaveMetadataValue(ctx, f.db, f.permissions, "admin", f.scope, f.id, f.field.ID, absent.Field.Revision, absent.Revision, "Stale empty editor", false)
	require.ErrorIs(t, err, inventory.ErrMetadataConflict)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, value := range []string{"First writer", "Second writer"} {
		go func() {
			<-start
			_, err := inventory.SaveMetadataValue(ctx, f.db, f.permissions, "admin", f.scope, f.id, f.field.ID, latest.Field.Revision, latest.Revision, value, false)
			results <- err
		}()
	}
	close(start)
	won, stale := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			won++
		} else if errors.Is(err, inventory.ErrMetadataConflict) {
			stale++
		} else {
			t.Fatal(err)
		}
	}
	require.Equal(t, 1, won)
	require.Equal(t, 1, stale)
	latest = f.read(t)
	_, err = f.db.ExecContext(ctx, `UPDATE metadata SET value='Temporary' WHERE agent_metadata=$1`, f.id)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `UPDATE metadata SET value=$2 WHERE agent_metadata=$1`, f.id, latest.Value)
	require.NoError(t, err)
	require.NotEqual(t, latest.Revision, f.read(t).Revision)
	latest = f.read(t)
	require.NoError(t, f.client.OrgMetadata.UpdateOneID(f.field.ID).SetDescription("New meaning").Exec(ctx))
	_, err = inventory.SaveMetadataValue(ctx, f.db, f.permissions, "admin", f.scope, f.id, f.field.ID, latest.Field.Revision, latest.Revision, "Stale meaning", false)
	require.ErrorIs(t, err, inventory.ErrMetadataConflict)
	for _, statement := range []string{`UPDATE uem_metadata_value_revisions SET revision=gen_random_uuid()`, `DELETE FROM uem_metadata_value_revisions`} {
		_, err = f.db.ExecContext(ctx, statement)
		require.Error(t, err)
	}
	before := f.read(t)
	require.NoError(t, f.client.Agent.DeleteOneID(f.id).Exec(ctx))
	var revision string
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT revision::text FROM uem_metadata_value_revisions WHERE device_id=$1 AND field_id=$2`, f.id, f.field.ID).Scan(&revision))
	require.NotEqual(t, before.Revision, revision)
}

func TestCustomMetadataCurrentScopeRolesAndHiddenReferences(t *testing.T) {
	f := newMetadataFixture(t)
	ctx := t.Context()
	first := f.read(t)
	for _, actor := range []string{"viewer", "operator", "missing"} {
		page, err := inventory.ListMetadataFields(ctx, f.db, f.permissions, actor, f.scope.TenantID, "", 0)
		require.ErrorIs(t, err, access.ErrDenied)
		require.Nil(t, page)
		value, err := inventory.ReadMetadataValue(ctx, f.db, f.permissions, actor, f.scope, f.id, f.field.ID)
		require.ErrorIs(t, err, access.ErrDenied)
		require.Nil(t, value)
		_, err = inventory.SaveMetadataValue(ctx, f.db, f.permissions, actor, f.scope, f.id, f.field.ID, first.Field.Revision, first.Revision, "Forbidden", false)
		require.ErrorIs(t, err, access.ErrDenied)
	}
	other, err := f.client.Tenant.Create().SetDescription("Foreign").Save(ctx)
	require.NoError(t, err)
	foreign, err := inventory.SaveMetadataField(ctx, f.db, f.permissions, "admin", other.ID, 0, "", "Foreign secret", "Private")
	require.NoError(t, err)
	_, err = inventory.ReadMetadataValue(ctx, f.db, f.permissions, "admin", f.scope, f.id, foreign.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	for _, change := range []string{"other-site", "foreign", "ambiguous", "orphan", "waiting", "missing"} {
		t.Run(change, func(t *testing.T) {
			f := newMetadataFixture(t)
			ctx := t.Context()
			first := f.read(t)
			id := f.id
			switch change {
			case "other-site":
				require.NoError(t, f.client.Agent.UpdateOneID(id).ClearSite().AddSiteIDs(f.otherSite).Exec(ctx))
			case "foreign":
				tenant, err := f.client.Tenant.Create().SetDescription("Foreign").Save(ctx)
				require.NoError(t, err)
				site, err := f.client.Site.Create().SetDescription("Foreign").SetTenantID(tenant.ID).Save(ctx)
				require.NoError(t, err)
				require.NoError(t, f.client.Agent.UpdateOneID(id).ClearSite().AddSiteIDs(site.ID).Exec(ctx))
			case "ambiguous":
				require.NoError(t, f.client.Agent.UpdateOneID(id).AddSiteIDs(f.otherSite).Exec(ctx))
			case "orphan":
				require.NoError(t, f.client.Agent.UpdateOneID(id).ClearSite().Exec(ctx))
			case "waiting":
				require.NoError(t, f.client.Agent.UpdateOneID(id).SetAgentStatus(agent.AgentStatusWaitingForAdmission).Exec(ctx))
			case "missing":
				id = "missing-device"
			}
			for _, actor := range []string{"admin", "metadata-admin"} {
				page, err := inventory.ListDeviceMetadata(ctx, f.db, f.permissions, actor, f.scope, id, "", 0)
				require.ErrorIs(t, err, inventory.ErrNotFound)
				require.Nil(t, page)
				value, err := inventory.ReadMetadataValue(ctx, f.db, f.permissions, actor, f.scope, id, f.field.ID)
				require.ErrorIs(t, err, inventory.ErrNotFound)
				require.Nil(t, value)
				_, err = inventory.SaveMetadataValue(ctx, f.db, f.permissions, actor, f.scope, id, f.field.ID, first.Field.Revision, first.Revision, "Must not save", false)
				require.ErrorIs(t, err, inventory.ErrNotFound)
			}
		})
	}
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "metadata-admin", 1, nil))
	_, err = inventory.ReadMetadataValue(ctx, f.db, f.permissions, "metadata-admin", f.scope, f.id, f.field.ID)
	require.ErrorIs(t, err, access.ErrDenied)
}

func TestCustomMetadataBoundsAndNoSilentTruncation(t *testing.T) {
	f := newMetadataFixture(t)
	ctx := t.Context()
	first := f.read(t)
	for _, name := range []string{"", "  ", strings.Repeat("é", 128), "new\nline", "bad\x00", string([]byte{0xff})} {
		_, err := inventory.SaveMetadataField(ctx, f.db, f.permissions, "admin", f.scope.TenantID, 0, "", name, "")
		require.ErrorIs(t, err, inventory.ErrMetadataInvalid)
	}
	for _, description := range []string{strings.Repeat("x", 4097), "bad\x01", string([]byte{0xff})} {
		_, err := inventory.SaveMetadataField(ctx, f.db, f.permissions, "admin", f.scope.TenantID, 0, "", "Valid", description)
		require.ErrorIs(t, err, inventory.ErrMetadataInvalid)
	}
	for _, value := range []string{strings.Repeat("x", inventory.MaxMetadataValueBytes+1), "bad\x00", string([]byte{0xff})} {
		_, err := inventory.SaveMetadataValue(ctx, f.db, f.permissions, "admin", f.scope, f.id, f.field.ID, first.Field.Revision, first.Revision, value, false)
		require.ErrorIs(t, err, inventory.ErrMetadataInvalid)
	}
	for _, revision := range []string{"", uuid.Nil.String(), "not-a-uuid", strings.ToUpper(first.Revision)} {
		_, err := inventory.SaveMetadataValue(ctx, f.db, f.permissions, "admin", f.scope, f.id, f.field.ID, first.Field.Revision, revision, "Value", false)
		require.ErrorIs(t, err, inventory.ErrMetadataInvalid)
	}
	max := strings.Repeat("x", inventory.MaxMetadataValueBytes-4) + "\n\t\r\n"
	require.Equal(t, max, f.save(t, first, max, false).Value)
	_, err := f.db.ExecContext(ctx, `UPDATE metadata SET value=$2 WHERE agent_metadata=$1`, f.id, strings.Repeat("x", inventory.MaxMetadataValueBytes+1))
	require.NoError(t, err)
	got, err := inventory.ReadMetadataValue(ctx, f.db, f.permissions, "admin", f.scope, f.id, f.field.ID)
	require.ErrorIs(t, err, inventory.ErrMetadataInvalid)
	require.Nil(t, got)
	_, err = f.db.ExecContext(ctx, `UPDATE org_metadata SET description=$2 WHERE id=$1`, f.field.ID, strings.Repeat("x", 4097))
	require.NoError(t, err)
	field, err := inventory.ReadMetadataField(ctx, f.db, f.permissions, "admin", f.scope.TenantID, f.field.ID)
	require.ErrorIs(t, err, inventory.ErrMetadataInvalid)
	require.Nil(t, field)
}

func TestCustomMetadataDeletionReviewAtomicCascadeAndExactRetry(t *testing.T) {
	f := newMetadataFixture(t)
	ctx := t.Context()
	value := f.save(t, f.read(t), "Private value", false)
	r := f.review(t)
	require.EqualValues(t, 1, r.ValueCount)
	require.Nil(t, r.CompletedAt)
	for _, statement := range []string{`UPDATE uem_metadata_field_deletions SET name='Changed'`, `DELETE FROM uem_metadata_field_deletions`} {
		_, err := f.db.ExecContext(ctx, statement)
		require.Error(t, err)
	}
	_, err := inventory.MetadataDeletionReceipt(ctx, f.db, f.permissions, "admin", f.scope.TenantID, f.field.ID, r.ID, true)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = inventory.MetadataDeletionReceipt(ctx, f.db, f.permissions, "metadata-admin", f.scope.TenantID, f.field.ID+1, r.ID, true)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	got, err := inventory.MetadataDeletionReceipt(ctx, f.db, f.permissions, "metadata-admin", f.scope.TenantID, f.field.ID, r.ID, true)
	require.NoError(t, err)
	require.NotNil(t, got.CompletedAt)
	retry, err := inventory.MetadataDeletionReceipt(ctx, f.db, f.permissions, "metadata-admin", f.scope.TenantID, f.field.ID, r.ID, true)
	require.NoError(t, err)
	require.Equal(t, got.CompletedAt, retry.CompletedAt)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM metadata WHERE org_metadata_metadata=$1`, f.field.ID).Scan(&count))
	require.Zero(t, count)
	var revision string
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT revision::text FROM uem_metadata_value_revisions WHERE device_id=$1 AND field_id=$2`, f.id, f.field.ID).Scan(&revision))
	require.NotEqual(t, value.Revision, revision)
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE action='inventory.metadata.field.delete' AND resource_id=$1`, r.ID).Scan(&count))
	require.Equal(t, 1, count)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "metadata-admin", 1, nil))
	_, err = inventory.MetadataDeletionReceipt(ctx, f.db, f.permissions, "metadata-admin", f.scope.TenantID, f.field.ID, r.ID, false)
	require.ErrorIs(t, err, access.ErrDenied)
}

func TestCustomMetadataDeletionRejectsChangedImpactAndUnsafeOwnership(t *testing.T) {
	for _, change := range []string{"value", "value-away-back", "absence-away-back", "field", "membership", "membership-away-back", "foreign", "orphan", "ambiguous", "expired"} {
		t.Run(change, func(t *testing.T) {
			f := newMetadataFixture(t)
			ctx := t.Context()
			if change != "absence-away-back" {
				f.save(t, f.read(t), "Original", false)
			}
			r := f.review(t)
			want := inventory.ErrMetadataConflict
			switch change {
			case "value":
				_, err := f.db.ExecContext(ctx, `UPDATE metadata SET value='Changed' WHERE agent_metadata=$1`, f.id)
				require.NoError(t, err)
			case "value-away-back":
				_, err := f.db.ExecContext(ctx, `UPDATE metadata SET value='Temporary' WHERE agent_metadata=$1`, f.id)
				require.NoError(t, err)
				_, err = f.db.ExecContext(ctx, `UPDATE metadata SET value='Original' WHERE agent_metadata=$1`, f.id)
				require.NoError(t, err)
			case "absence-away-back":
				f.save(t, f.read(t), "Temporary", false)
				f.save(t, f.read(t), "", true)
			case "field":
				require.NoError(t, f.client.OrgMetadata.UpdateOneID(f.field.ID).SetDescription("Changed meaning").Exec(ctx))
			case "membership-away-back":
				require.NoError(t, f.client.Agent.UpdateOneID(f.id).ClearSite().AddSiteIDs(f.otherSite).Exec(ctx))
				require.NoError(t, f.client.Agent.UpdateOneID(f.id).ClearSite().AddSiteIDs(f.scope.SiteID).Exec(ctx))
			case "membership":
				require.NoError(t, f.client.Agent.UpdateOneID(f.id).ClearSite().AddSiteIDs(f.otherSite).Exec(ctx))
			case "foreign":
				tenant, err := f.client.Tenant.Create().SetDescription("Foreign").Save(ctx)
				require.NoError(t, err)
				require.NoError(t, f.client.Site.UpdateOneID(f.scope.SiteID).SetTenantID(tenant.ID).Exec(ctx))
				want = inventory.ErrMetadataUnsafeReferences
			case "orphan":
				require.NoError(t, f.client.Agent.UpdateOneID(f.id).ClearSite().Exec(ctx))
				want = inventory.ErrMetadataUnsafeReferences
			case "ambiguous":
				require.NoError(t, f.client.Agent.UpdateOneID(f.id).AddSiteIDs(f.otherSite).Exec(ctx))
				want = inventory.ErrMetadataUnsafeReferences
			case "expired":
				require.NoError(t, f.db.QueryRowContext(ctx, `INSERT INTO uem_metadata_field_deletions(tenant_id,field_id,field_revision,actor,name,description,value_count,source_hash,created_at,expires_at) SELECT tenant_id,field_id,field_revision,actor,name,description,value_count,source_hash,clock_timestamp()-interval '20 minutes',clock_timestamp()-interval '10 minutes' FROM uem_metadata_field_deletions WHERE id=$1 RETURNING id::text`, r.ID).Scan(&r.ID))
			}
			out, err := inventory.MetadataDeletionReceipt(ctx, f.db, f.permissions, "metadata-admin", f.scope.TenantID, f.field.ID, r.ID, true)
			require.ErrorIs(t, err, want)
			require.Nil(t, out)
			if want == inventory.ErrMetadataUnsafeReferences {
				_, err = inventory.ReviewMetadataDeletion(ctx, f.db, f.permissions, "admin", f.scope.TenantID, f.field.ID, f.field.Revision)
				require.ErrorIs(t, err, want)
			}
			var count int
			require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM metadata WHERE org_metadata_metadata=$1`, f.field.ID).Scan(&count))
			if change == "absence-away-back" {
				require.Zero(t, count)
			} else {
				require.Equal(t, 1, count)
			}
		})
	}
}

func TestCustomMetadataAuditFailureWithholdsReadsAndRollsBackMutations(t *testing.T) {
	f := newMetadataFixture(t)
	ctx := t.Context()
	value := f.save(t, f.read(t), "Retained", false)
	r := f.review(t)
	_, err := f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT metadata_audit_failure CHECK(action NOT LIKE 'inventory.metadata.%') NOT VALID`)
	require.NoError(t, err)
	field, err := inventory.SaveMetadataField(ctx, f.db, f.permissions, "admin", f.scope.TenantID, f.field.ID, f.field.Revision, "Must roll back", "")
	require.Error(t, err)
	require.Nil(t, field)
	field, err = inventory.SaveMetadataField(ctx, f.db, f.permissions, "admin", f.scope.TenantID, 0, "", "Must not exist", "")
	require.Error(t, err)
	require.Nil(t, field)
	page, err := inventory.ListMetadataFields(ctx, f.db, f.permissions, "admin", f.scope.TenantID, "", 0)
	require.Error(t, err)
	require.Nil(t, page)
	device, err := inventory.ListDeviceMetadata(ctx, f.db, f.permissions, "admin", f.scope, f.id, "", 0)
	require.Error(t, err)
	require.Nil(t, device)
	read, err := inventory.ReadMetadataValue(ctx, f.db, f.permissions, "admin", f.scope, f.id, f.field.ID)
	require.Error(t, err)
	require.Nil(t, read)
	for _, clear := range []bool{false, true} {
		draft := "Must roll back"
		if clear {
			draft = ""
		}
		out, err := inventory.SaveMetadataValue(ctx, f.db, f.permissions, "admin", f.scope, f.id, f.field.ID, value.Field.Revision, value.Revision, draft, clear)
		require.Error(t, err)
		require.Nil(t, out)
	}
	out, err := inventory.ReviewMetadataDeletion(ctx, f.db, f.permissions, "admin", f.scope.TenantID, f.field.ID, f.field.Revision)
	require.Error(t, err)
	require.Nil(t, out)
	out, err = inventory.MetadataDeletionReceipt(ctx, f.db, f.permissions, "metadata-admin", f.scope.TenantID, f.field.ID, r.ID, true)
	require.Error(t, err)
	require.Nil(t, out)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT metadata_audit_failure`)
	require.NoError(t, err)
	latest := f.read(t)
	require.Equal(t, value, latest)
	receipt, err := inventory.MetadataDeletionReceipt(ctx, f.db, f.permissions, "metadata-admin", f.scope.TenantID, f.field.ID, r.ID, false)
	require.NoError(t, err)
	require.Nil(t, receipt.CompletedAt)
}

func TestCustomMetadataKeepAuthorityOwnershipAndLegacyValuesThroughAudit(t *testing.T) {
	for _, write := range []bool{false, true} {
		t.Run(fmt.Sprint(write), func(t *testing.T) {
			f := newMetadataFixture(t)
			first := f.read(t)
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			blocker, err := f.db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer blocker.Rollback()
			_, err = blocker.ExecContext(ctx, `LOCK TABLE uem_inventory_audit IN SHARE MODE`)
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() {
				var err error
				if write {
					_, err = inventory.SaveMetadataValue(ctx, f.db, f.permissions, "metadata-admin", f.scope, f.id, f.field.ID, first.Field.Revision, first.Revision, "Committed", false)
				} else {
					_, err = inventory.ReadMetadataValue(ctx, f.db, f.permissions, "metadata-admin", f.scope, f.id, f.field.ID)
				}
				done <- err
			}()
			wait := func(n int, auditOnly bool) {
				t.Helper()
				require.Eventually(t, func() bool {
					var count int
					err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE NOT l.granted AND a.application_name=current_setting('application_name') AND (NOT $1 OR (l.relation='uem_inventory_audit'::regclass AND l.mode='RowExclusiveLock'))`, auditOnly).Scan(&count)
					return err == nil && count >= n
				}, 3*time.Second, 10*time.Millisecond)
			}
			wait(1, true)
			changed := make(chan error, 3)
			go func() { changed <- f.permissions.ReplaceGrants(ctx, "admin", "metadata-admin", 1, nil) }()
			go func() {
				_, err := f.db.ExecContext(ctx, `INSERT INTO site_agents(site_id,agent_id) VALUES($1,$2)`, f.otherSite, f.id)
				changed <- err
			}()
			go func() {
				_, err := f.db.ExecContext(ctx, `INSERT INTO metadata(value,agent_metadata,org_metadata_metadata) VALUES('Later writer',$1,$2) ON CONFLICT(org_metadata_metadata,agent_metadata) DO UPDATE SET value=EXCLUDED.value`, f.id, f.field.ID)
				changed <- err
			}()
			wait(4, false)
			select {
			case err := <-changed:
				t.Fatal("change overtook metadata audit", err)
			default:
			}
			require.NoError(t, blocker.Commit())
			require.NoError(t, <-done)
			for range 3 {
				require.NoError(t, <-changed)
			}
		})
	}
}

func TestCustomMetadataReadingAnUnsetValueDoesNotInvalidateDeletion(t *testing.T) {
	f := newMetadataFixture(t)
	r := f.review(t)
	require.False(t, f.read(t).Present)
	out, err := inventory.MetadataDeletionReceipt(t.Context(), f.db, f.permissions, "metadata-admin", f.scope.TenantID, f.field.ID, r.ID, true)
	require.NoError(t, err)
	require.NotNil(t, out.CompletedAt)
}

func TestCustomMetadataAuditsMaximumLengthDeviceIDs(t *testing.T) {
	f := newMetadataFixture(t)
	id := strings.Repeat("d", 255)
	require.NoError(t, f.client.Agent.Create().SetID(id).SetHostname("Long identifier").SetOs("linux").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(t.Context()))
	v, err := inventory.ReadMetadataValue(t.Context(), f.db, f.permissions, "admin", f.scope, id, f.field.ID)
	require.NoError(t, err)
	_, err = inventory.SaveMetadataValue(t.Context(), f.db, f.permissions, "admin", f.scope, id, f.field.ID, v.Field.Revision, v.Revision, "Value", false)
	require.NoError(t, err)
}
