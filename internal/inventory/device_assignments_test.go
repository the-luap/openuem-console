package inventory_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func assignmentFixture(t *testing.T) (*refreshFixture, access.Scope) {
	f := newSoftwareFixture(t)
	ctx := t.Context()
	tenant, err := f.client.Tenant.Create().SetDescription("Destination organization").Save(ctx)
	require.NoError(t, err)
	site, err := f.client.Site.Create().SetDescription("Destination site").SetTenantID(tenant.ID).Save(ctx)
	require.NoError(t, err)
	tag, err := f.client.Tag.Create().SetTag("Source tag").SetColor("red").SetTenantID(f.scope.TenantID).Save(ctx)
	require.NoError(t, err)
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).AddTagIDs(tag.ID).SetNotes("Retained device notes").Exec(ctx))
	definition, err := f.client.OrgMetadata.Create().SetName("Private source field").SetDescription("Private definition").Save(ctx)
	require.NoError(t, err)
	require.NoError(t, f.client.Metadata.Create().SetOwnerID(f.id).SetOrgID(definition.ID).SetValue("Private source value").Exec(ctx))
	return f, access.Scope{TenantID: tenant.ID, SiteID: site.ID}
}

func assignmentCounts(t *testing.T, f *refreshFixture) (int, int, int) {
	t.Helper()
	var site, tags, metadata int
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT site_id FROM site_agents WHERE agent_id=$1`, f.id).Scan(&site))
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM agent_tags WHERE agent_id=$1`, f.id).Scan(&tags))
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM metadata WHERE agent_metadata=$1`, f.id).Scan(&metadata))
	return site, tags, metadata
}

func TestDeviceAssignmentAtomicMoveAndExactRetry(t *testing.T) {
	f, target := assignmentFixture(t)
	ctx := t.Context()
	choices, err := inventory.ReadDeviceAssignmentChoices(ctx, f.db, f.permissions, "admin", f.scope, f.id, "Destination", 0)
	require.NoError(t, err)
	require.Len(t, choices.Locations, 1)
	require.Equal(t, target.SiteID, choices.Locations[0].SiteID)
	r, err := inventory.ReviewDeviceAssignment(ctx, f.db, f.permissions, "admin", f.scope, f.id, target.SiteID)
	require.NoError(t, err)
	require.EqualValues(t, 1, r.TagCount)
	require.EqualValues(t, 1, r.MetadataCount)
	site, tags, metadata := assignmentCounts(t, f)
	require.Equal(t, f.scope.SiteID, site)
	require.Equal(t, 1, tags)
	require.Equal(t, 1, metadata)
	got, err := inventory.DeviceAssignmentReceipt(ctx, f.db, f.permissions, "admin", f.scope, f.id, r.ID, true)
	require.NoError(t, err)
	require.NotNil(t, got.CompletedAt)
	site, tags, metadata = assignmentCounts(t, f)
	require.Equal(t, target.SiteID, site)
	require.Zero(t, tags)
	require.Zero(t, metadata)
	stored, err := f.client.Agent.Get(ctx, f.id)
	require.NoError(t, err)
	require.Equal(t, "Retained device notes", stored.Notes)
	retry, err := inventory.DeviceAssignmentReceipt(ctx, f.db, f.permissions, "admin", f.scope, f.id, r.ID, true)
	require.NoError(t, err)
	require.Equal(t, got.CompletedAt, retry.CompletedAt)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE action IN ('inventory.assignment.depart','inventory.assignment.arrive') AND resource_id=$1 AND ((tenant_id=$2 AND site_id=$3) OR (tenant_id=$4 AND site_id=$5))`, r.ID, f.scope.TenantID, f.scope.SiteID, target.TenantID, target.SiteID).Scan(&count))
	require.Equal(t, 2, count)
	_, err = f.db.ExecContext(ctx, `UPDATE uem_device_assignment_reviews SET target_site=$2 WHERE id=$1`, r.ID, f.otherSite)
	require.Error(t, err)
	_, err = f.db.ExecContext(ctx, `DELETE FROM uem_device_assignment_reviews WHERE id=$1`, r.ID)
	require.Error(t, err)
}

func TestDeviceAssignmentChangedImpactAndAuditFailurePreserveSource(t *testing.T) {
	f, target := assignmentFixture(t)
	ctx := t.Context()
	review := func() *inventory.DeviceAssignmentReview {
		r, err := inventory.ReviewDeviceAssignment(ctx, f.db, f.permissions, "admin", f.scope, f.id, target.SiteID)
		require.NoError(t, err)
		return r
	}
	r := review()
	_, err := f.db.ExecContext(ctx, `UPDATE metadata SET value='Changed private value' WHERE agent_metadata=$1`, f.id)
	require.NoError(t, err)
	got, err := inventory.DeviceAssignmentReceipt(ctx, f.db, f.permissions, "admin", f.scope, f.id, r.ID, true)
	require.ErrorIs(t, err, inventory.ErrAssignmentChanged)
	require.Nil(t, got)
	r = review()
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT assignment_audit_failure CHECK(action<>'inventory.assignment.arrive') NOT VALID`)
	require.NoError(t, err)
	got, err = inventory.DeviceAssignmentReceipt(ctx, f.db, f.permissions, "admin", f.scope, f.id, r.ID, true)
	require.Error(t, err)
	require.Nil(t, got)
	site, tags, metadata := assignmentCounts(t, f)
	require.Equal(t, f.scope.SiteID, site)
	require.Equal(t, 1, tags)
	require.Equal(t, 1, metadata)
	var completed bool
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT completed_at IS NOT NULL FROM uem_device_assignment_reviews WHERE id=$1`, r.ID).Scan(&completed))
	require.False(t, completed)
}

func TestDeviceAssignmentOrganizationAuthorityAndRetainedSameOrganizationData(t *testing.T) {
	f, foreign := assignmentFixture(t)
	ctx := t.Context()
	require.NoError(t, f.client.User.Create().SetID("assignment-admin").SetName("Assignment administrator").SetEmail("assignment@example.test").SetUse2fa(false).Exec(ctx))
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "assignment-admin", 0, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: f.scope.TenantID}}}))
	for _, actor := range []string{"viewer", "operator", "missing"} {
		out, err := inventory.ReadDeviceAssignmentChoices(ctx, f.db, f.permissions, actor, f.scope, f.id, "", 0)
		require.ErrorIs(t, err, access.ErrDenied)
		require.Nil(t, out)
		_, err = inventory.ReviewDeviceAssignment(ctx, f.db, f.permissions, actor, f.scope, f.id, f.otherSite)
		require.ErrorIs(t, err, access.ErrDenied)
	}
	choices, err := inventory.ReadDeviceAssignmentChoices(ctx, f.db, f.permissions, "assignment-admin", f.scope, f.id, "", 0)
	require.NoError(t, err)
	require.Len(t, choices.Locations, 1)
	require.Equal(t, f.otherSite, choices.Locations[0].SiteID)
	_, err = inventory.ReviewDeviceAssignment(ctx, f.db, f.permissions, "assignment-admin", f.scope, f.id, foreign.SiteID)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = inventory.ReviewDeviceAssignment(ctx, f.db, f.permissions, "admin", f.scope, f.id, f.scope.SiteID)
	require.ErrorIs(t, err, inventory.ErrAssignmentInvalid)
	_, err = inventory.ReviewDeviceAssignment(ctx, f.db, f.permissions, "admin", f.scope, f.id, 9999999)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	r, err := inventory.ReviewDeviceAssignment(ctx, f.db, f.permissions, "assignment-admin", f.scope, f.id, f.otherSite)
	require.NoError(t, err)
	_, err = inventory.DeviceAssignmentReceipt(ctx, f.db, f.permissions, "admin", f.scope, f.id, r.ID, true)
	require.ErrorIs(t, err, inventory.ErrNotFound, "another actor reused the confirmation")
	_, err = inventory.DeviceAssignmentReceipt(ctx, f.db, f.permissions, "assignment-admin", f.scope, f.id, r.ID, true)
	require.NoError(t, err)
	site, tags, metadata := assignmentCounts(t, f)
	require.Equal(t, f.otherSite, site)
	require.Equal(t, 1, tags)
	require.Equal(t, 1, metadata)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "assignment-admin", 1, nil))
	_, err = inventory.DeviceAssignmentReceipt(ctx, f.db, f.permissions, "assignment-admin", f.scope, f.id, r.ID, true)
	require.ErrorIs(t, err, access.ErrDenied)
}

func TestDeviceAssignmentReviewRejectsChangedAndHiddenSources(t *testing.T) {
	for _, change := range []string{"tag", "notes", "scope-away-and-back", "status", "destination", "ambiguous", "orphan", "waiting"} {
		t.Run(change, func(t *testing.T) {
			f, target := assignmentFixture(t)
			ctx := t.Context()
			r, err := inventory.ReviewDeviceAssignment(ctx, f.db, f.permissions, "admin", f.scope, f.id, target.SiteID)
			require.NoError(t, err)
			switch change {
			case "tag":
				_, err = f.db.ExecContext(ctx, `UPDATE tags SET tag='Changed tag' WHERE id IN (SELECT tag_id FROM agent_tags WHERE agent_id=$1)`, f.id)
			case "notes":
				err = f.client.Agent.UpdateOneID(f.id).SetNotes("New confidential notes").Exec(ctx)
			case "scope-away-and-back":
				err = f.client.Agent.UpdateOneID(f.id).ClearSite().AddSiteIDs(f.otherSite).Exec(ctx)
				require.NoError(t, err)
				err = f.client.Agent.UpdateOneID(f.id).ClearSite().AddSiteIDs(f.scope.SiteID).Exec(ctx)
			case "status":
				err = f.client.Agent.UpdateOneID(f.id).SetAgentStatus(agent.AgentStatusDisabled).Exec(ctx)
			case "destination":
				err = f.client.Site.UpdateOneID(target.SiteID).SetTenantID(f.scope.TenantID).Exec(ctx)
			case "ambiguous":
				err = f.client.Agent.UpdateOneID(f.id).AddSiteIDs(f.otherSite).Exec(ctx)
			case "orphan":
				err = f.client.Agent.UpdateOneID(f.id).ClearSite().Exec(ctx)
			case "waiting":
				err = f.client.Agent.UpdateOneID(f.id).SetAgentStatus(agent.AgentStatusWaitingForAdmission).Exec(ctx)
			}
			require.NoError(t, err)
			got, err := inventory.DeviceAssignmentReceipt(ctx, f.db, f.permissions, "admin", f.scope, f.id, r.ID, true)
			require.ErrorIs(t, err, inventory.ErrAssignmentChanged)
			require.Nil(t, got)
			var count int
			require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM metadata WHERE agent_metadata=$1`, f.id).Scan(&count))
			require.Equal(t, 1, count)
		})
	}
}

func TestDeviceAssignmentIndividualIdentityCannotBeRewrittenAsLegacyInventory(t *testing.T) {
	f, target := assignmentFixture(t)
	ctx := t.Context()
	identities, err := registry.NewStore(f.db, strings.Repeat("a", 32))
	require.NoError(t, err)
	require.NoError(t, identities.Migrate(ctx))
	_, err = identities.EnsureAuthority(ctx, f.scope.TenantID, "Assignment fixture", "https://uem.example.test", "admin", nil, nil)
	require.NoError(t, err)
	invitation, err := identities.Invite(ctx, registry.InvitationOptions{Scope: registry.Scope{TenantID: f.scope.TenantID, SiteID: f.scope.SiteID}, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	require.NoError(t, err)
	keys, err := enrollment.GenerateKeys()
	require.NoError(t, err)
	defer keys.Broker.Wipe()
	claim, err := keys.Request(invitation.URL[strings.LastIndex(invitation.URL, "/")+1:], "windows", "amd64", "Individual assignment fixture")
	require.NoError(t, err)
	response, err := identities.Claim(ctx, *claim)
	require.NoError(t, err)
	device := response.DeviceID
	require.NoError(t, f.client.Agent.Create().SetID(device).SetHostname("Individual device").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(ctx))
	for _, revoked := range []bool{false, true} {
		if revoked {
			_, err = f.db.ExecContext(ctx, `UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1`, device)
			require.NoError(t, err)
		}
		choices, err := inventory.ReadDeviceAssignmentChoices(ctx, f.db, f.permissions, "admin", f.scope, device, "", 0)
		require.NoError(t, err)
		require.True(t, choices.IndividualIdentity)
		require.Empty(t, choices.Locations)
		got, err := inventory.ReviewDeviceAssignment(ctx, f.db, f.permissions, "admin", f.scope, device, target.SiteID)
		require.ErrorIs(t, err, inventory.ErrAssignmentIdentity)
		require.Nil(t, got)
	}
}

func TestDeviceAssignmentConcurrentConfirmationAndExpiry(t *testing.T) {
	f, target := assignmentFixture(t)
	ctx := t.Context()
	r, err := inventory.ReviewDeviceAssignment(ctx, f.db, f.permissions, "admin", f.scope, f.id, target.SiteID)
	require.NoError(t, err)
	expired := uuid.NewString()
	_, err = f.db.ExecContext(ctx, `INSERT INTO uem_device_assignment_reviews(id,device_id,actor,source_tenant,source_site,target_tenant,target_site,device_name,source_organization,source_location,target_organization,target_location,tag_count,metadata_count,source_hash,created_at,expires_at)
 SELECT $2,device_id,actor,source_tenant,source_site,target_tenant,target_site,device_name,source_organization,source_location,target_organization,target_location,tag_count,metadata_count,source_hash,clock_timestamp()-interval '20 minutes',clock_timestamp()-interval '10 minutes' FROM uem_device_assignment_reviews WHERE id=$1`, r.ID, expired)
	require.NoError(t, err)
	got, err := inventory.DeviceAssignmentReceipt(ctx, f.db, f.permissions, "admin", f.scope, f.id, expired, true)
	require.ErrorIs(t, err, inventory.ErrAssignmentChanged)
	require.Nil(t, got)
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := inventory.DeviceAssignmentReceipt(ctx, f.db, f.permissions, "admin", f.scope, f.id, r.ID, true)
			results <- err
		}()
	}
	close(start)
	require.NoError(t, <-results)
	require.NoError(t, <-results)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE action IN ('inventory.assignment.depart','inventory.assignment.arrive') AND resource_id=$1`, r.ID).Scan(&count))
	require.Equal(t, 2, count)
}

func TestDeviceAssignmentKeepsPermissionDestinationAndDataLocksThroughAudit(t *testing.T) {
	f, _ := assignmentFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	require.NoError(t, f.client.User.Create().SetID("assignment-admin").SetName("Assignment administrator").SetEmail("assignment@example.test").SetUse2fa(false).Exec(ctx))
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "assignment-admin", 0, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: f.scope.TenantID}}}))
	r, err := inventory.ReviewDeviceAssignment(ctx, f.db, f.permissions, "assignment-admin", f.scope, f.id, f.otherSite)
	require.NoError(t, err)
	blocker, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer blocker.Rollback()
	_, err = blocker.ExecContext(ctx, `LOCK TABLE uem_inventory_audit IN SHARE MODE`)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := inventory.DeviceAssignmentReceipt(ctx, f.db, f.permissions, "assignment-admin", f.scope, f.id, r.ID, true)
		done <- err
	}()
	wait := func(want int, auditOnly bool) {
		t.Helper()
		require.Eventually(t, func() bool {
			var n int
			err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE NOT l.granted AND a.application_name=current_setting('application_name') AND (NOT $1 OR (l.relation='uem_inventory_audit'::regclass AND l.mode='RowExclusiveLock'))`, auditOnly).Scan(&n)
			return err == nil && n >= want
		}, 3*time.Second, 10*time.Millisecond)
	}
	// Other schemas share the permission advisory lock. Wait for this move's
	// audit insertion specifically, after it has acquired every data lock.
	wait(1, true)
	changed := make(chan error, 3)
	go func() { changed <- f.permissions.ReplaceGrants(ctx, "admin", "assignment-admin", 1, nil) }()
	go func() {
		_, err := f.db.ExecContext(ctx, `UPDATE sites SET description='Later destination name' WHERE id=$1`, f.otherSite)
		changed <- err
	}()
	go func() {
		_, err := f.db.ExecContext(ctx, `UPDATE metadata SET value='Later metadata' WHERE agent_metadata=$1`, f.id)
		changed <- err
	}()
	wait(4, false)
	select {
	case err := <-changed:
		t.Fatal("a permission, destination or metadata change overtook the audit", err)
	default:
	}
	require.NoError(t, blocker.Commit())
	require.NoError(t, <-done)
	for range 3 {
		require.NoError(t, <-changed)
	}
}
