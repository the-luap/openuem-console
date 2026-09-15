package windows

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestUpdateRingRolloutConcurrentRetriesAndAuditRollback(t *testing.T) {
	f := syncMLTestStore(t)
	ring := updateTestRing(t, f, updateTestPolicy())
	ctx := context.Background()
	if _, err := f.store.db.Exec(`CREATE FUNCTION reject_ring_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic ring audit failure'; END; $$; CREATE TRIGGER reject_ring_audit BEFORE INSERT ON mdm_windows_update_ring_audit FOR EACH ROW EXECUTE FUNCTION reject_ring_audit()`); err != nil {
		t.Fatal(err)
	}
	if r, err := f.store.AssignUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), []string{f.identity.DeviceID}, false, time.Hour); err == nil || r != nil {
		t.Fatal("unaudited rollout returned work")
	}
	if r, err := f.store.SaveUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, uuid.NewString(), 1, "Unaudited revision", updateTestPolicy(), true); err == nil || r != nil {
		t.Fatal("unaudited ring revision committed")
	}
	if r, err := f.store.SaveUpdateRing(ctx, "operator", f.identity.Scope, uuid.NewString(), uuid.NewString(), 0, "Unaudited creation", updateTestPolicy(), true); err == nil || r != nil {
		t.Fatal("unaudited ring creation committed")
	}
	if r, err := f.store.UpdateRingRevisions(ctx, "operator", f.identity.Scope, ring.RingID, 0, 10); err == nil || r != nil {
		t.Fatal("unaudited history returned payload")
	}
	if r, err := f.store.UpdateRings(ctx, "operator", f.identity.Scope, 0, 10); err == nil || r != nil {
		t.Fatal("unaudited catalog returned payload")
	}
	var runs, commands, rollouts, rings, revisions int
	if err := f.store.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_windows_update_runs),(SELECT count(*) FROM mdm_windows_csp_commands),(SELECT count(*) FROM mdm_windows_update_rollouts),(SELECT count(*) FROM mdm_windows_update_rings),(SELECT count(*) FROM mdm_windows_update_ring_revisions)`).Scan(&runs, &commands, &rollouts, &rings, &revisions); err != nil || runs != 0 || commands != 0 || rollouts != 0 || rings != 1 || revisions != 1 {
		t.Fatal("audit failure left partial ring work", err)
	}
	if _, err := f.store.db.Exec(`DROP TRIGGER reject_ring_audit ON mdm_windows_update_ring_audit`); err != nil {
		t.Fatal(err)
	}
	key := uuid.NewString()
	type result struct {
		r   *UpdateRollout
		err error
	}
	results := make(chan result, 6)
	var workers sync.WaitGroup
	for i := 0; i < 6; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			r, err := f.store.AssignUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, key, []string{f.identity.DeviceID}, false, time.Hour)
			results <- result{r, err}
		}()
	}
	workers.Wait()
	close(results)
	var first *UpdateRollout
	for result := range results {
		if result.err != nil {
			t.Fatal("concurrent rollout retry failed", result.err)
		}
		if first == nil {
			first = result.r
		} else if !reflect.DeepEqual(first, result.r) {
			t.Fatal("concurrent retry created multiple cohorts")
		}
	}
	if err := f.store.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_windows_update_runs),(SELECT count(*) FROM mdm_windows_csp_commands),(SELECT count(*) FROM mdm_windows_update_rollouts)`).Scan(&runs, &commands, &rollouts); err != nil || runs != 1 || commands != 5 || rollouts != 1 {
		t.Fatal("concurrent cohort retry added work", err)
	}
	if _, err := f.store.db.Exec(`CREATE TRIGGER reject_ring_audit BEFORE INSERT ON mdm_windows_update_ring_audit FOR EACH ROW EXECUTE FUNCTION reject_ring_audit()`); err != nil {
		t.Fatal(err)
	}
	if r, err := f.store.UpdateRolloutDetails(ctx, "operator", f.identity.Scope, first.ID); err == nil || r != nil {
		t.Fatal("unaudited rollout read returned protected targets")
	}
	if r, err := f.store.AssignUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, key, []string{f.identity.DeviceID}, false, time.Hour); err == nil || r != nil {
		t.Fatal("unaudited rollout retry returned work")
	}
}

func TestUpdateRingSourceProofRejectsChangedPolicyMembershipAndCiphertext(t *testing.T) {
	f := syncMLTestStore(t)
	ring := updateTestRing(t, f, updateTestPolicy())
	ctx := context.Background()
	cohort, err := f.store.AssignUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), []string{f.identity.DeviceID}, false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	run, err := scanUpdateRun(f.store.db.QueryRow(`SELECT `+updateRunColumns+` FROM mdm_windows_update_runs WHERE id=$1`, cohort.Runs[0].ID))
	if err != nil {
		t.Fatal(err)
	}
	intent, err := f.store.openUpdateRun(run)
	if err != nil {
		t.Fatal(err)
	}
	changed := *run
	changed.RolloutID = uuid.NewString()
	if _, err := f.store.openUpdateRun(&changed); err == nil {
		t.Fatal("run ciphertext moved to another cohort")
	}
	changed = *run
	changed.RingID = ""
	changed.RingRevision = 0
	changed.RolloutID = ""
	if _, err := f.store.openUpdateRun(&changed); err == nil {
		t.Fatal("ring-bound ciphertext became direct intent")
	}
	if _, err := f.store.db.Exec(`UPDATE mdm_windows_update_runs SET ring_id=NULL,ring_revision=NULL,rollout_id=NULL WHERE id=$1`, run.ID); err == nil {
		t.Fatal("SQL detached admitted ring provenance")
	}
	tx, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := f.store.validateUpdateRunSource(ctx, tx, run, intent); err != nil {
		t.Fatal(err)
	}
	newIntent := *intent
	newIntent.Policy = updateTestFullPolicy()
	if err := f.store.validateUpdateRunSource(ctx, tx, run, &newIntent); !errors.Is(err, ErrAuthoritySecret) {
		t.Fatal("ring source authorized a different valid typed policy", err)
	}
	changed = *run
	changed.DeviceID = uuid.NewString()
	changed.RequestKey = updateRolloutRequest(cohort.ID, changed.DeviceID)
	if err := f.store.validateUpdateRunSource(ctx, tx, &changed, intent); !errors.Is(err, ErrAuthoritySecret) {
		t.Fatal("ring source authorized an unreviewed target", err)
	}
	source, err := scanUpdateRollout(tx.QueryRowContext(ctx, `SELECT `+updateRolloutColumns+` FROM mdm_windows_update_rollouts WHERE id=$1`, cohort.ID))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(source.encrypted, []byte(f.identity.DeviceID)) {
		t.Fatal("reviewed target list stored in plaintext")
	}
	source.RingRevision++
	if err := f.store.openUpdateRollout(source); err == nil {
		t.Fatal("cohort ciphertext moved to a different revision")
	}
	if data, err := json.Marshal(cohort); err != nil || string(data) != "{}" {
		t.Fatal("generic serialization exposed protected rollout", err)
	}
}

func TestUpdateRingMigrationPreservesActiveDirectRunReplay(t *testing.T) {
	f := syncMLTestStore(t)
	policy := updateTestPolicy()
	run := updateTestQueue(t, f, policy, false)
	request, response := cspTestStart(t, f)
	updateTestRemoveRingMigration(t, f.store)
	for n := 0; n < 2; n++ {
		if err := f.store.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if replay, err := f.process(request); err != nil || !bytes.Equal(replay, response) {
		t.Fatal("ring migration rewrote existing delivery authority", err)
	}
	for step := 0; step < 5; step++ {
		var err error
		response, err = f.process(syncMLTestWire(t, updateTestReply(syncMLTestParsed(t, response), policy, false, false)))
		if err != nil {
			t.Fatal("existing direct run failed after ring upgrade", step, err)
		}
	}
	if detail := updateTestRead(t, f, run.ID); detail.Phase != "verified" || detail.Run.RingID != "" {
		t.Fatal("upgrade attached new source semantics to old intent", detail.Phase)
	}
}
