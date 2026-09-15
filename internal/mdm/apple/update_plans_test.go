package apple

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func ownedUpdatePlanDefinition() UpdatePlanDefinition {
	return UpdatePlanDefinition{Name: "Owned <pilot>", Description: "Owned reviewed update", Platform: "ios", TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: "2026-10-01T18:00:00", DetailsURL: "https://example.test/owned/update"}
}
func TestUpdatePlanDefinitionBounds(t *testing.T) {
	for _, field := range []string{"name", "description", "platform", "version", "build", "deadline", "offset", "url", "credentials", "control", "unicode", "url-size"} {
		t.Run(field, func(t *testing.T) {
			d := ownedUpdatePlanDefinition()
			require.True(t, d.Valid())
			switch field {
			case "name":
				d.Name = " "
			case "description":
				d.Description = strings.Repeat("d", 1025)
			case "platform":
				d.Platform = "windows"
			case "version":
				d.TargetVersion = "latest"
			case "build":
				d.TargetBuild = "22H100/extra"
			case "deadline":
				d.Deadline = "2026-10-01T18:00"
			case "offset":
				d.Deadline = "2026-10-01T18:00:00Z"
			case "url":
				d.DetailsURL = "http://example.test/update"
			case "credentials":
				d.DetailsURL = "https://user:password@example.test/update"
			case "control":
				d.Name = "Owned\nplan"
			case "unicode":
				d.Name = string([]byte{0xff})
			case "url-size":
				d.DetailsURL = "https://example.test/" + strings.Repeat("x", 2048)
			}
			require.False(t, d.Valid())
		})
	}
}

func TestUpdatePlanHistoryConcurrentRevisionAndScope(t *testing.T) {
	s, permissions, _, _ := profileAssignmentAccessFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	definition := ownedUpdatePlanDefinition()
	_, err := s.SaveUpdatePlan(ctx, "viewer", permissions, scope, "", 0, definition)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = s.SaveUpdatePlan(ctx, "admin", nil, scope, "", 0, definition)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = s.SaveUpdatePlan(ctx, "admin", permissions, Scope{TenantID: 1}, "", 0, definition)
	require.ErrorIs(t, err, access.ErrDenied)
	p, err := s.SaveUpdatePlan(ctx, "operator", permissions, scope, "", 0, definition)
	require.NoError(t, err)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := definition
			d.Name = "Owned revised pilot"
			_, err := s.SaveUpdatePlan(ctx, "operator", permissions, scope, p.ID, 1, d)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else {
			require.ErrorIs(t, err, ErrConflict)
			conflict++
		}
	}
	require.Equal(t, 1, success)
	require.Equal(t, 1, conflict)
	current, history, next, err := s.UpdatePlanHistory(ctx, "viewer", permissions, scope, p.ID, 0)
	require.NoError(t, err)
	require.Equal(t, 2, current.Revision)
	require.Len(t, history, 2)
	require.Zero(t, next)
	require.Equal(t, definition, history[1].Definition)
	archived := current.Definition
	archived.Archived = true
	current, err = s.SaveUpdatePlan(ctx, "operator", permissions, scope, p.ID, current.Revision, archived)
	require.NoError(t, err)
	require.True(t, current.Definition.Archived)
	for _, protected := range []any{current, current.Definition} {
		encoded, err := json.Marshal(protected)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(encoded))
	}
	var encrypted []byte
	require.NoError(t, s.db.QueryRow(`SELECT encrypted_definition FROM mdm_apple_update_plan_revisions WHERE plan_id=$1 AND revision=1`, p.ID).Scan(&encrypted))
	require.False(t, strings.Contains(string(encrypted), definition.Name))
	require.False(t, strings.Contains(string(encrypted), definition.DetailsURL))
	_, err = s.db.Exec(`UPDATE mdm_apple_update_plan_revisions SET actor='viewer' WHERE plan_id=$1`, p.ID)
	require.Error(t, err)
	_, err = s.db.Exec(`DELETE FROM mdm_apple_update_plans WHERE id=$1`, p.ID)
	require.Error(t, err)
	_, err = s.db.Exec(`UPDATE mdm_apple_update_plans SET site_id=2 WHERE id=$1`, p.ID)
	require.Error(t, err)
	var count int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_policies`).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE request_type='DeclarativeManagement' AND status='queued'`).Scan(&count))
	require.Zero(t, count)
	_, err = s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`)
	require.NoError(t, err)
	_, _, _, err = s.UpdatePlanHistory(ctx, "admin", permissions, scope, p.ID, 0)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = s.SaveUpdatePlan(ctx, "admin", permissions, scope, p.ID, current.Revision, definition)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestUpdatePlanPaginationAndAuditRollback(t *testing.T) {
	s, permissions, _, _ := profileAssignmentAccessFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	definition := ownedUpdatePlanDefinition()
	var p *UpdatePlan
	for i := 0; i < 26; i++ {
		var err error
		p, err = s.SaveUpdatePlan(ctx, "operator", permissions, scope, "", 0, definition)
		require.NoError(t, err)
	}
	first, next, err := s.UpdatePlans(ctx, "viewer", permissions, scope, "")
	require.NoError(t, err)
	require.Len(t, first, 25)
	require.NotEmpty(t, next)
	last, next, err := s.UpdatePlans(ctx, "viewer", permissions, scope, next)
	require.NoError(t, err)
	require.Len(t, last, 1)
	require.Empty(t, next)
	_, _, err = s.UpdatePlans(ctx, "viewer", permissions, scope, uuid.NewString())
	require.ErrorIs(t, err, ErrNotFound)
	for i := 0; i < 25; i++ {
		p, err = s.SaveUpdatePlan(ctx, "operator", permissions, scope, p.ID, p.Revision, definition)
		require.NoError(t, err)
	}
	current, history, older, err := s.UpdatePlanHistory(ctx, "viewer", permissions, scope, p.ID, 0)
	require.NoError(t, err)
	require.Equal(t, 26, current.Revision)
	require.Len(t, history, 25)
	require.Equal(t, 2, older)
	_, history, older, err = s.UpdatePlanHistory(ctx, "viewer", permissions, scope, p.ID, older)
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.Zero(t, older)
	_, _, _, err = s.UpdatePlanHistory(ctx, "viewer", permissions, scope, p.ID, 27)
	require.ErrorIs(t, err, ErrUpdatePlan)
	_, err = s.db.Exec(`CREATE FUNCTION owned_update_plan_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action LIKE 'apple.update.plan.%' THEN RAISE EXCEPTION 'owned update plan audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_update_plan_audit_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_update_plan_audit_failure()`)
	require.NoError(t, err)
	_, err = s.SaveUpdatePlan(ctx, "operator", permissions, scope, p.ID, 26, definition)
	require.Error(t, err)
	var head, revisions int
	require.NoError(t, s.db.QueryRow(`SELECT revision FROM mdm_apple_update_plans WHERE id=$1`, p.ID).Scan(&head))
	require.Equal(t, 26, head)
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_plan_revisions WHERE plan_id=$1`, p.ID).Scan(&revisions))
	require.Equal(t, 26, revisions)
	plans, _, err := s.UpdatePlans(ctx, "viewer", permissions, scope, "")
	require.Error(t, err)
	require.Nil(t, plans)
	current, history, _, err = s.UpdatePlanHistory(ctx, "viewer", permissions, scope, p.ID, 0)
	require.Error(t, err)
	require.Nil(t, current)
	require.Nil(t, history)
}

func TestUpdatePlanCiphertextBindsImmutableRevisionAndIdentity(t *testing.T) {
	s, permissions, _, _ := profileAssignmentAccessFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	p, err := s.SaveUpdatePlan(ctx, "operator", permissions, scope, "", 0, ownedUpdatePlanDefinition())
	require.NoError(t, err)
	tx, err := s.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.Exec(`UPDATE mdm_apple_update_plans SET revision=2 WHERE id=$1`, p.ID)
	require.NoError(t, err)
	_, err = tx.Exec(`INSERT INTO mdm_apple_update_plan_revisions(plan_id,tenant_id,site_id,revision,actor,created_at,encrypted_definition) SELECT plan_id,tenant_id,site_id,2,actor,created_at,encrypted_definition FROM mdm_apple_update_plan_revisions WHERE plan_id=$1 AND revision=1`, p.ID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	current, history, _, err := s.UpdatePlanHistory(ctx, "viewer", permissions, scope, p.ID, 0)
	require.ErrorIs(t, err, ErrUpdatePlanIntegrity)
	require.Nil(t, current)
	require.Nil(t, history)
}

func TestUpdatePlanScopeLimitRetainsExistingRevisionWork(t *testing.T) {
	s, permissions, _, _ := profileAssignmentAccessFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	definition := ownedUpdatePlanDefinition()
	p, err := s.SaveUpdatePlan(ctx, "operator", permissions, scope, "", 0, definition)
	require.NoError(t, err)
	// Unreadable owned rows exercise admission count without constructing a
	// thousand plans. The test never reads or deploys these placeholder sources.
	tx, err := s.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO mdm_apple_update_plans(id,tenant_id,site_id,revision) SELECT gen_random_uuid(),1,1,1 FROM generate_series(1,999)`)
	require.NoError(t, err)
	_, err = tx.Exec(`INSERT INTO mdm_apple_update_plan_revisions(plan_id,tenant_id,site_id,revision,actor,created_at,encrypted_definition) SELECT id,1,1,1,'admin',clock_timestamp(),decode(repeat('ab',29),'hex') FROM mdm_apple_update_plans WHERE id<>$1`, p.ID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	_, err = s.SaveUpdatePlan(ctx, "operator", permissions, scope, "", 0, definition)
	require.ErrorIs(t, err, ErrUpdatePlanLimit)
	definition.Archived = true
	_, err = s.SaveUpdatePlan(ctx, "operator", permissions, scope, p.ID, p.Revision, definition)
	require.NoError(t, err)
}
