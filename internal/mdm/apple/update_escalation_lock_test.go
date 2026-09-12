package apple

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUpdateEscalationKeepsDeviceAndAuthorityLocksThroughFinalAudit(t *testing.T) {
	f, original, q := ownedUpdateEscalationFixture(t)
	ctx := t.Context()
	_, err := f.store.ConfigureUpdateEscalation(ctx, "operator", f.permissions, f.scope, q)
	require.NoError(t, err)
	const gate = 673810051
	blocker, err := f.store.db.Conn(ctx)
	require.NoError(t, err)
	defer blocker.Close()
	_, err = blocker.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, gate)
	require.NoError(t, err)
	defer blocker.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gate)
	_, err = f.store.db.Exec(`CREATE FUNCTION owned_escalation_audit_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.escalation.checked' THEN PERFORM pg_advisory_xact_lock(673810051); END IF; RETURN NEW; END $$; CREATE TRIGGER owned_escalation_audit_wait BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_escalation_audit_wait()`)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { _, err := f.store.ProcessDueUpdateEscalations(ctx, f.permissions, 25); done <- err }()
	require.Eventually(t, func() bool {
		var waiting bool
		err := f.store.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=$1 AND NOT granted)`, gate).Scan(&waiting)
		return err == nil && waiting
	}, 3*time.Second, 10*time.Millisecond)
	// Both changes are valid but cannot overtake the assessment's final audit.
	policyCtx, cancelPolicy := context.WithTimeout(ctx, 200*time.Millisecond)
	err = f.store.SetUpdatePolicyWithAccess(policyCtx, f.scope, []string{f.device.ID}, nil, "operator", f.permissions)
	cancelPolicy()
	require.Error(t, err)
	grantCtx, cancelGrant := context.WithTimeout(ctx, 200*time.Millisecond)
	err = f.permissions.ReplaceGrants(grantCtx, "admin", "operator", 1, nil)
	cancelGrant()
	require.Error(t, err)
	_, err = blocker.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gate)
	require.NoError(t, err)
	select {
	case err = <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("monitoring did not finish after releasing its audit")
	}
	r := ownedEscalationDetails(t, f, original)
	require.Equal(t, 1, r.OpenCount)
	require.Equal(t, "attention", r.Snapshot.Devices[0].Decision.State)
	require.NoError(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, nil, "operator", f.permissions))
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "operator", 1, nil))
	ownedEscalationDue(t, f, original)
	require.Equal(t, 1, ownedEscalationProcess(t, f).Blocked)
	blocked := ownedEscalationDetails(t, f, original)
	require.Equal(t, "authority_changed", blocked.Reason)
	require.Equal(t, r.IncidentID, blocked.IncidentID)
}
