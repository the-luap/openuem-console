package inventory_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestProfileEditorHoldsReadSourceAndAuthorityUntilReceipt(t *testing.T) {
	f, organization := tagFixture(t)
	ctx := t.Context()
	principal, err := f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Administrator}}))
	principal, err = f.permissions.Principal(ctx, "tag-admin")
	require.NoError(t, err)
	g := ownedDeletionGraph(t, f, f.scope)
	choice, err := f.client.Tag.Create().SetTag("Held available choice").SetColor("blue").SetTenantID(f.scope.TenantID).Save(ctx)
	require.NoError(t, err)
	conn, err := f.db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock(673810076)")
	require.NoError(t, err)
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(673810076)")
			_ = conn.Close()
		})
	}
	t.Cleanup(release)
	_, err = f.db.ExecContext(ctx, `CREATE SEQUENCE owned_editor_entered; CREATE FUNCTION hold_owned_editor() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.profiles.read' THEN PERFORM nextval('owned_editor_entered'); PERFORM pg_advisory_xact_lock(673810076); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_owned_editor AFTER INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION hold_owned_editor()`)
	require.NoError(t, err)
	type outcome struct {
		review *inventory.ProfileEditorReview
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		r, err := inventory.ReadProfileEditor(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(g.profile), 1, 5, inventory.ProfileTagQuery{Page: 1})
		done <- outcome{r, err}
	}()
	require.Eventually(t, func() bool {
		var entered bool
		return f.db.QueryRowContext(ctx, "SELECT is_called FROM owned_editor_entered").Scan(&entered) == nil && entered
	}, 2*time.Second, 10*time.Millisecond)
	select {
	case <-done:
		t.Fatal("read returned before audit commit")
	default:
	}
	for _, mutation := range []func(context.Context) error{
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "UPDATE profiles SET name='Concurrent name' WHERE id=$1", g.profile)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "UPDATE tasks SET name='Concurrent task' WHERE id=$1", g.task)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "INSERT INTO tasks(name,type,disabled,profile_tasks) VALUES('New task','unix_script',false,$1)", g.profile)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "DELETE FROM profile_tags WHERE profile_id=$1", g.profile)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "INSERT INTO profile_tags(profile_id,tag_id) VALUES($1,$2)", g.profile, choice.ID)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "UPDATE tags SET tag='Changed applied tag' WHERE id=$1", g.tag)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "UPDATE tags SET tenant_tags=NULL WHERE id=$1", choice.ID)
			return err
		},
		func(ctx context.Context) error {
			_, err := f.db.ExecContext(ctx, "DELETE FROM site_profiles WHERE profile_id=$1", g.profile)
			return err
		},
		func(ctx context.Context) error {
			return f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: organization}})
		},
	} {
		bounded, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
		require.Error(t, mutation(bounded))
		cancel()
	}
	release()
	select {
	case result := <-done:
		require.NoError(t, result.err)
		require.NotNil(t, result.review)
		require.Equal(t, 1, result.review.Tags.Total)
	case <-time.After(2 * time.Second):
		t.Fatal("profile read did not leave audit gate")
	}
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "tag-admin", principal.Revision, []access.Grant{{Role: access.Viewer, Scope: organization}}))
	result, err := inventory.ReadProfileEditor(ctx, f.db, f.permissions, "tag-admin", f.scope, int64(g.profile), 1, 5, inventory.ProfileTagQuery{Page: 1})
	require.ErrorIs(t, err, access.ErrDenied)
	require.Nil(t, result)
	assertDeletionGraph(t, f, g, true)
}
