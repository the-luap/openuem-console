package inventory_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func newNotesFixture(t *testing.T) *refreshFixture {
	f := newSoftwareFixture(t)
	require.NoError(t, f.client.User.Create().SetID("notes-admin").SetName("Notes administrator").SetEmail("notes@example.test").SetUse2fa(false).Exec(t.Context()))
	require.NoError(t, f.permissions.ReplaceGrants(t.Context(), "admin", "notes-admin", 0, []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: f.scope.TenantID}}}))
	return f
}

func TestDeviceNotesRevisionAuditAndConcurrentEdits(t *testing.T) {
	f := newNotesFixture(t)
	ctx := t.Context()
	read := func() *inventory.DeviceNotes {
		notes, err := inventory.ReadDeviceNotes(ctx, f.db, f.permissions, "notes-admin", f.scope, f.id)
		require.NoError(t, err)
		return notes
	}
	first := read()
	require.Empty(t, first.Notes)
	require.NotEmpty(t, first.Revision)
	const secret = "Private project & contacts\n\t**Markdown**\r\n"
	updated, err := inventory.UpdateDeviceNotes(ctx, f.db, f.permissions, "notes-admin", f.scope, f.id, first.Revision, secret)
	require.NoError(t, err)
	require.NotEqual(t, first.Revision, updated.Revision)
	require.Equal(t, secret, read().Notes)
	unchanged, err := inventory.UpdateDeviceNotes(ctx, f.db, f.permissions, "admin", f.scope, f.id, updated.Revision, secret)
	require.NoError(t, err)
	require.Equal(t, updated.Revision, unchanged.Revision)
	// A normal agent report must not invalidate a notes-only edit.
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetHostname("New hostname").Exec(ctx))
	require.Equal(t, updated.Revision, read().Revision)
	_, err = f.db.ExecContext(ctx, `UPDATE agents SET uem_notes_revision=$2 WHERE oid=$1`, f.id, uuid.NewString())
	require.Error(t, err)
	// An older writer still changes the protected revision.
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetNotes("Legacy update").Exec(ctx))
	legacy := read()
	require.NotEqual(t, updated.Revision, legacy.Revision)
	got, err := inventory.UpdateDeviceNotes(ctx, f.db, f.permissions, "notes-admin", f.scope, f.id, updated.Revision, "Stale draft")
	require.ErrorIs(t, err, inventory.ErrDeviceNotesConflict)
	require.Nil(t, got)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, draft := range []string{"First writer", "Second writer"} {
		go func() {
			<-start
			_, err := inventory.UpdateDeviceNotes(ctx, f.db, f.permissions, "notes-admin", f.scope, f.id, legacy.Revision, draft)
			results <- err
		}()
	}
	close(start)
	won, stale := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			won++
		} else if errors.Is(err, inventory.ErrDeviceNotesConflict) {
			stale++
		} else {
			t.Fatal(err)
		}
	}
	require.Equal(t, 1, won)
	require.Equal(t, 1, stale)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE action='inventory.notes.update' AND tenant_id=$1 AND site_id=$2 AND resource_id LIKE $3`, f.scope.TenantID, f.scope.SiteID, f.id+"/%").Scan(&count))
	require.Equal(t, 3, count)
	var leaked bool
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_inventory_audit a WHERE row_to_json(a)::text LIKE '%Private project%' OR row_to_json(a)::text LIKE '%Stale draft%')`).Scan(&leaked))
	require.False(t, leaked)
}

func TestDeviceNotesScopePermissionsAndValidation(t *testing.T) {
	f := newNotesFixture(t)
	ctx := t.Context()
	first, err := inventory.ReadDeviceNotes(ctx, f.db, f.permissions, "notes-admin", f.scope, f.id)
	require.NoError(t, err)
	for _, actor := range []string{"viewer", "operator", "missing"} {
		got, err := inventory.ReadDeviceNotes(ctx, f.db, f.permissions, actor, f.scope, f.id)
		require.ErrorIs(t, err, access.ErrDenied)
		require.Nil(t, got)
		got, err = inventory.UpdateDeviceNotes(ctx, f.db, f.permissions, actor, f.scope, f.id, first.Revision, "Denied")
		require.ErrorIs(t, err, access.ErrDenied)
		require.Nil(t, got)
	}
	for _, notes := range []string{strings.Repeat("a", inventory.MaxDeviceNotesBytes+1), "NUL\x00", "control\x01", string([]byte{0xff})} {
		got, err := inventory.UpdateDeviceNotes(ctx, f.db, f.permissions, "notes-admin", f.scope, f.id, first.Revision, notes)
		require.ErrorIs(t, err, inventory.ErrDeviceNotesInvalid)
		require.Nil(t, got)
	}
	for _, revision := range []string{"", "bad", uuid.Nil.String(), "F531367C-00BC-4F1A-A8ED-6162D9923716"} {
		_, err := inventory.UpdateDeviceNotes(ctx, f.db, f.permissions, "notes-admin", f.scope, f.id, revision, "Valid")
		require.ErrorIs(t, err, inventory.ErrDeviceNotesInvalid)
	}
	foreign, err := f.client.Tenant.Create().SetDescription("Foreign organization").Save(ctx)
	require.NoError(t, err)
	foreignSite, err := f.client.Site.Create().SetDescription("Foreign site").SetTenantID(foreign.ID).Save(ctx)
	require.NoError(t, err)
	for _, state := range []string{"foreign", "ambiguous", "same-organization-ambiguous", "waiting", "orphan"} {
		update := f.client.Agent.UpdateOneID(f.id).ClearSite().SetAgentStatus(agent.AgentStatusEnabled)
		switch state {
		case "foreign":
			update.AddSiteIDs(foreignSite.ID)
		case "ambiguous":
			update.AddSiteIDs(f.scope.SiteID, foreignSite.ID)
		case "same-organization-ambiguous":
			update.AddSiteIDs(f.scope.SiteID, f.otherSite)
		case "waiting":
			update.AddSiteIDs(f.scope.SiteID).SetAgentStatus(agent.AgentStatusWaitingForAdmission)
		}
		require.NoError(t, update.Exec(ctx))
		for _, scope := range []access.Scope{f.scope, {TenantID: f.scope.TenantID}} {
			got, err := inventory.ReadDeviceNotes(ctx, f.db, f.permissions, "notes-admin", scope, f.id)
			require.ErrorIs(t, err, inventory.ErrNotFound, state)
			require.Nil(t, got)
			got, err = inventory.UpdateDeviceNotes(ctx, f.db, f.permissions, "notes-admin", scope, f.id, first.Revision, "Hidden update")
			require.ErrorIs(t, err, inventory.ErrNotFound, state)
			require.Nil(t, got)
		}
	}
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).ClearSite().AddSiteIDs(f.scope.SiteID).SetAgentStatus(agent.AgentStatusDisabled).Exec(ctx))
	_, err = inventory.UpdateDeviceNotes(ctx, f.db, f.permissions, "notes-admin", f.scope, f.id, first.Revision, strings.Repeat("é", inventory.MaxDeviceNotesBytes/2))
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "notes-admin", 1, nil))
	got, err := inventory.ReadDeviceNotes(ctx, f.db, f.permissions, "notes-admin", f.scope, f.id)
	require.ErrorIs(t, err, access.ErrDenied)
	require.Nil(t, got)
}

func TestDeviceNotesAuditFailureRollsBackAndWithholdsContent(t *testing.T) {
	f := newNotesFixture(t)
	ctx := t.Context()
	require.NoError(t, f.client.Agent.UpdateOneID(f.id).SetNotes("Keep this private").Exec(ctx))
	before, err := inventory.ReadDeviceNotes(ctx, f.db, f.permissions, "notes-admin", f.scope, f.id)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT notes_audit_failure CHECK(action NOT IN ('inventory.notes.read','inventory.notes.update')) NOT VALID`)
	require.NoError(t, err)
	got, err := inventory.ReadDeviceNotes(ctx, f.db, f.permissions, "notes-admin", f.scope, f.id)
	require.Error(t, err)
	require.Nil(t, got)
	got, err = inventory.UpdateDeviceNotes(ctx, f.db, f.permissions, "notes-admin", f.scope, f.id, before.Revision, "Must roll back")
	require.Error(t, err)
	require.Nil(t, got)
	var notes, revision string
	require.NoError(t, f.db.QueryRowContext(ctx, `SELECT notes,uem_notes_revision::text FROM agents WHERE oid=$1`, f.id).Scan(&notes, &revision))
	require.Equal(t, before.Notes, notes)
	require.Equal(t, before.Revision, revision)
}

func TestDeviceNotesHoldPermissionAndMembershipUntilAuditCommit(t *testing.T) {
	for _, write := range []bool{false, true} {
		name := "read"
		if write {
			name = "write"
		}
		t.Run(name, func(t *testing.T) {
			f := newNotesFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			before, err := inventory.ReadDeviceNotes(ctx, f.db, f.permissions, "notes-admin", f.scope, f.id)
			require.NoError(t, err)
			blocker, err := f.db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer blocker.Rollback()
			_, err = blocker.ExecContext(ctx, `LOCK TABLE uem_inventory_audit IN SHARE MODE`)
			require.NoError(t, err)
			finished := make(chan error, 1)
			go func() {
				var err error
				if write {
					_, err = inventory.UpdateDeviceNotes(ctx, f.db, f.permissions, "notes-admin", f.scope, f.id, before.Revision, "Atomic update")
				} else {
					_, err = inventory.ReadDeviceNotes(ctx, f.db, f.permissions, "notes-admin", f.scope, f.id)
				}
				finished <- err
			}()
			waitLocks := func(want int) {
				t.Helper()
				require.Eventually(t, func() bool {
					var count int
					err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE NOT l.granted AND a.application_name=current_setting('application_name')`).Scan(&count)
					return err == nil && count >= want
				}, 3*time.Second, 10*time.Millisecond)
			}
			waitLocks(1)
			revoked, moved := make(chan error, 1), make(chan error, 1)
			go func() { revoked <- f.permissions.ReplaceGrants(ctx, "admin", "notes-admin", 1, nil) }()
			go func() {
				_, err := f.db.ExecContext(ctx, `INSERT INTO site_agents(site_id,agent_id) VALUES($1,$2)`, f.otherSite, f.id)
				moved <- err
			}()
			waitLocks(3)
			select {
			case err := <-revoked:
				t.Fatal("revocation overtook notes audit", err)
			default:
			}
			select {
			case err := <-moved:
				t.Fatal("membership overtook notes audit", err)
			default:
			}
			require.NoError(t, blocker.Commit())
			require.NoError(t, <-finished)
			require.NoError(t, <-revoked)
			require.NoError(t, <-moved)
			got, err := inventory.ReadDeviceNotes(ctx, f.db, f.permissions, "notes-admin", f.scope, f.id)
			require.ErrorIs(t, err, access.ErrDenied)
			require.Nil(t, got)
		})
	}
}
