package inventory_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/ent/agent"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/stretchr/testify/require"
)

func TestDesktopTagAssignmentRejectsForeignOrganization(t *testing.T) {
	f, _ := tagFixture(t)
	ctx := t.Context()
	foreign, err := f.client.Tenant.Create().SetDescription("Other tag organization").Save(ctx)
	require.NoError(t, err)
	tag, err := f.client.Tag.Create().SetTag("Foreign tag").SetColor("red").SetTenantID(foreign.ID).Save(ctx)
	require.NoError(t, err)
	err = inventory.ChangeDesktopTag(ctx, f.db, f.permissions, "admin", f.scope, f.id, int64(tag.ID), true)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM agent_tags WHERE agent_id=$1`, f.id).Scan(&count))
	require.Zero(t, count)
	// Old invalid associations can be removed, without allowing new ones.
	require.ErrorIs(t, inventory.ChangeDesktopTag(ctx, f.db, f.permissions, "admin", f.scope, f.id, int64(tag.ID), false), inventory.ErrNotFound)
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).AddTagIDs(tag.ID).Exec(ctx))
	require.NoError(t, inventory.ChangeDesktopTag(ctx, f.db, f.permissions, "admin", f.scope, f.id, int64(tag.ID), false))
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM agent_tags WHERE agent_id=$1`, f.id).Scan(&count))
	require.Zero(t, count)
}

func TestDesktopTagAssignmentScopeStatusAndPermissions(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	tag, err := f.client.Tag.Create().SetTag("Scoped desktop tag").SetColor("blue").SetTenantID(organization.TenantID).Save(ctx)
	require.NoError(t, err)
	change := func(actor string, scope access.Scope, assigned bool) error {
		return inventory.ChangeDesktopTag(ctx, f.db, f.permissions, actor, scope, f.id, int64(tag.ID), assigned)
	}
	for _, actor := range []string{"tag-admin", "tag-viewer", "tag-operator", "operator", "viewer", "missing"} {
		require.ErrorIs(t, change(actor, f.scope, true), access.ErrDenied)
	}
	for _, scope := range []access.Scope{{}, {TenantID: -1}, {TenantID: organization.TenantID, SiteID: -1}} {
		require.ErrorIs(t, change("admin", scope, true), access.ErrDenied)
	}
	require.ErrorIs(t, change("admin", access.Scope{TenantID: organization.TenantID, SiteID: f.otherSite}, true), inventory.ErrNotFound)
	other, err := f.client.Tenant.Create().SetDescription("Wrong device organization").Save(ctx)
	require.NoError(t, err)
	require.ErrorIs(t, change("admin", access.Scope{TenantID: other.ID}, true), inventory.ErrNotFound)
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).AddSiteIDs(f.otherSite).Exec(ctx))
	require.ErrorIs(t, change("admin", organization, true), inventory.ErrNotFound)
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).ClearSite().Exec(ctx))
	require.ErrorIs(t, change("admin", organization, true), inventory.ErrNotFound)
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).AddSiteIDs(f.scope.SiteID).SetAgentStatus(agent.AgentStatusWaitingForAdmission).Exec(ctx))
	require.ErrorIs(t, change("admin", f.scope, true), inventory.ErrNotFound)
	for _, status := range []agent.AgentStatus{agent.AgentStatusEnabled, agent.AgentStatusDisabled, agent.AgentStatusNoContact} {
		require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetAgentStatus(status).Exec(ctx))
		require.NoError(t, change("admin", organization, true))
		require.NoError(t, change("admin", organization, false))
	}
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE action IN ('inventory.tags.assign','inventory.tags.unassign') AND tenant_id=$1 AND site_id=$2`, f.scope.TenantID, f.scope.SiteID).Scan(&count))
	require.Equal(t, 6, count)
}

func TestDesktopTagAssignmentPreservesOtherMembershipsAndAuditRollback(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	var ids []int64
	for i := 0; i < 3; i++ {
		tag, err := f.client.Tag.Create().SetTag(fmt.Sprintf("Independent tag %d", i)).SetColor("red").SetTenantID(organization.TenantID).Save(ctx)
		require.NoError(t, err)
		ids = append(ids, int64(tag.ID))
	}
	change := func(parent context.Context, id int64, assigned bool) error {
		return inventory.ChangeDesktopTag(parent, f.db, f.permissions, "admin", f.scope, f.id, id, assigned)
	}
	// Concurrent set operations retain different memberships and serialize retries.
	var wg sync.WaitGroup
	results := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Go(func() { results <- change(ctx, ids[i%3], true) })
	}
	wg.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	count := func() int {
		var n int
		require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM agent_tags WHERE agent_id=$1`, f.id).Scan(&n))
		return n
	}
	require.Equal(t, 3, count())
	for i := 0; i < 2; i++ {
		require.NoError(t, change(ctx, ids[0], false))
	}
	require.Equal(t, 2, count())
	_, err := f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT owned_assignment_audit_failure CHECK(action NOT IN ('inventory.tags.assign','inventory.tags.unassign')) NOT VALID`)
	require.NoError(t, err)
	require.Error(t, change(ctx, ids[0], true))
	require.Error(t, change(ctx, ids[1], false))
	require.Equal(t, 2, count())
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT owned_assignment_audit_failure`)
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	require.Error(t, change(canceled, ids[1], false))
	require.Equal(t, 2, count())
	// The longest supported legacy device ID remains fully identifiable in audit.
	longID := strings.Repeat("L", 255)
	require.NoError(t, f.client.Agent.Create().SetID(longID).SetHostname("Long legacy ID").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(f.scope.SiteID).Exec(ctx))
	require.NoError(t, inventory.ChangeDesktopTag(ctx, f.db, f.permissions, "admin", f.scope, longID, ids[0], true))
	var resource, revision string
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT uem_revision::text FROM tags WHERE id=$1`, ids[0]).Scan(&revision))
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT resource_id FROM uem_inventory_audit WHERE action='inventory.tags.assign' ORDER BY id DESC LIMIT 1`).Scan(&resource))
	require.Equal(t, fmt.Sprintf("%s/%d/%s", longID, ids[0], revision), resource)
	audits, err := audit.NewStore(f.db, f.permissions)
	require.NoError(t, err)
	filter := audit.Filter{Scope: f.scope, Source: "inventory", Action: "inventory.tags.assign", Resource: resource, From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
	page, err := audits.List(ctx, "admin", filter, "")
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	require.Equal(t, resource, page.Events[0].Resource)
	exported, err := audits.ExportJSON(ctx, "admin", filter)
	require.NoError(t, err)
	require.Contains(t, string(exported), resource)
	filter.Scope.SiteID = f.otherSite
	page, err = audits.List(ctx, "admin", filter, "")
	require.NoError(t, err)
	require.Empty(t, page.Events)
}

func TestDesktopTagAssignmentWaitsForCurrentTagAndDeviceScope(t *testing.T) {
	for _, source := range []string{"tag", "site", "membership", "device"} {
		t.Run(source, func(t *testing.T) {
			f, scope := tagFixture(t)
			ctx := t.Context()
			tag, err := f.client.Tag.Create().SetTag("Locked tag").SetColor("blue").SetTenantID(scope.TenantID).Save(ctx)
			require.NoError(t, err)
			tx, err := f.db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer tx.Rollback()
			switch source {
			case "tag":
				_, err = tx.ExecContext(ctx, `UPDATE tags SET tenant_tags=NULL WHERE id=$1`, tag.ID)
			case "site":
				_, err = tx.ExecContext(ctx, `UPDATE sites SET tenant_sites=NULL WHERE id=$1`, f.scope.SiteID)
			case "membership":
				_, err = tx.ExecContext(ctx, `INSERT INTO site_agents(agent_id,site_id) VALUES($1,$2)`, f.id, f.otherSite)
			case "device":
				_, err = tx.ExecContext(ctx, `UPDATE agents SET agent_status='WaitingForAdmission' WHERE oid=$1`, f.id)
			}
			require.NoError(t, err)
			bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
			err = inventory.ChangeDesktopTag(bounded, f.db, f.permissions, "admin", f.scope, f.id, int64(tag.ID), true)
			cancel()
			require.Error(t, err)
			require.NoError(t, tx.Commit())
			require.ErrorIs(t, inventory.ChangeDesktopTag(ctx, f.db, f.permissions, "admin", f.scope, f.id, int64(tag.ID), true), inventory.ErrNotFound)
		})
	}
}

func TestDesktopTagAssignmentHoldsAuthorityThroughAuditCommit(t *testing.T) {
	f, scope := tagFixture(t)
	ctx := t.Context()
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Administrator}}))
	principal, err = f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	tag, err := f.client.Tag.Create().SetTag("Audited assignment").SetColor("blue").SetTenantID(scope.TenantID).Save(ctx)
	require.NoError(t, err)
	conn, err := f.db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock(673810061)`)
	require.NoError(t, err)
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(673810061)`)
			_ = conn.Close()
		})
	}
	t.Cleanup(release)
	_, err = f.db.ExecContext(ctx, `CREATE SEQUENCE owned_tag_assignment_entered; CREATE FUNCTION hold_owned_tag_assignment() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.tags.assign' THEN PERFORM nextval('owned_tag_assignment_entered'); PERFORM pg_advisory_xact_lock(673810061); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_owned_tag_assignment AFTER INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION hold_owned_tag_assignment()`)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		done <- inventory.ChangeDesktopTag(ctx, f.db, f.permissions, "tag-admin", f.scope, f.id, int64(tag.ID), true)
	}()
	require.Eventually(t, func() bool {
		var entered bool
		return f.db.QueryRowContext(ctx, `SELECT is_called FROM owned_tag_assignment_entered`).Scan(&entered) == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
	for _, mutation := range []func(context.Context) error{
		func(ctx context.Context) error {
			return f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: scope}})
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `UPDATE tags SET tenant_tags=NULL WHERE id=$1`, tag.ID)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `UPDATE sites SET tenant_sites=NULL WHERE id=$1`, f.scope.SiteID)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `INSERT INTO site_agents(agent_id,site_id) VALUES($1,$2)`, f.id, f.otherSite)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, `UPDATE agents SET agent_status='WaitingForAdmission' WHERE oid=$1`, f.id)
			return err
		},
	} {
		bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
		require.Error(t, mutation(bounded))
		cancel()
	}
	release()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("tag assignment did not leave its audit gate")
	}
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: scope}}))
	require.ErrorIs(t, inventory.ChangeDesktopTag(ctx, f.db, f.permissions, "tag-admin", f.scope, f.id, int64(tag.ID), false), access.ErrDenied)
}
