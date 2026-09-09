package windows

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func updateTestRemoveRingMigration(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.db.Exec(`DROP TABLE mdm_windows_update_ring_audit; ALTER TABLE mdm_windows_update_runs DROP COLUMN ring_id,DROP COLUMN ring_revision,DROP COLUMN rollout_id; DROP TABLE mdm_windows_update_rollouts; ALTER TABLE mdm_windows_update_rings DROP CONSTRAINT mdm_windows_update_ring_head; DROP TABLE mdm_windows_update_ring_revisions,mdm_windows_update_rings; DROP FUNCTION mdm_windows_keep_update_ring(); DELETE FROM mdm_windows_migrations WHERE name='migrations/008_update_rings.sql'`); err != nil {
		t.Fatal(err)
	}
}

func updateTestRing(t *testing.T, f syncMLStoreFixture, policy UpdatePolicy) *UpdateRingRevision {
	t.Helper()
	r, err := f.store.SaveUpdateRing(context.Background(), "operator", f.identity.Scope, uuid.NewString(), uuid.NewString(), 0, "Synthetic pilot ring", policy, true)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestUpdateRingConcurrentRevisionRetriesAndProtectedHistory(t *testing.T) {
	f := syncMLTestStore(t)
	ctx := context.Background()
	id, key := uuid.NewString(), uuid.NewString()
	type result struct {
		r   *UpdateRingRevision
		err error
	}
	results := make(chan result, 6)
	var workers sync.WaitGroup
	for i := 0; i < 6; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			r, err := f.store.SaveUpdateRing(ctx, "operator", f.identity.Scope, id, key, 0, "Synthetic pilot ring", updateTestPolicy(), true)
			results <- result{r, err}
		}()
	}
	workers.Wait()
	close(results)
	for result := range results {
		if result.err != nil || result.r.Revision != 1 {
			t.Fatal("concurrent creation changed revision", result.err)
		}
	}
	policy := updateTestFullPolicy()
	edits := make(chan result, 2)
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			r, err := f.store.SaveUpdateRing(ctx, "operator", f.identity.Scope, id, uuid.NewString(), 1, "Synthetic broad ring", policy, true)
			edits <- result{r, err}
		}()
	}
	workers.Wait()
	close(edits)
	var next *UpdateRingRevision
	conflicts := 0
	for edit := range edits {
		if errors.Is(edit.err, ErrUpdateRingConflict) {
			conflicts++
		} else if edit.err != nil || edit.r.Revision != 2 || next != nil {
			t.Fatal("concurrent edit bypassed the reviewed revision", edit.err)
		} else {
			next = edit.r
		}
	}
	if next == nil || conflicts != 1 {
		t.Fatal("concurrent edits did not select exactly one successor")
	}
	if _, err := f.store.SaveUpdateRing(ctx, "operator", f.identity.Scope, id, uuid.NewString(), 1, "Stale edit", policy, true); !errors.Is(err, ErrUpdateRingConflict) {
		t.Fatal("stale review overwrote newer revision", err)
	}
	if _, err := f.store.SaveUpdateRing(ctx, "operator", f.identity.Scope, id, key, 0, "Changed retry", updateTestPolicy(), true); !errors.Is(err, ErrUpdateRingConflict) {
		t.Fatal("request reuse changed protected intent", err)
	}
	if old, err := f.store.SaveUpdateRing(ctx, "operator", f.identity.Scope, id, key, 0, "Synthetic pilot ring", updateTestPolicy(), true); err != nil || old.Revision != 1 {
		t.Fatal("later edit broke original retry", err)
	}
	current, err := f.store.UpdateRings(ctx, "operator", f.identity.Scope, 0, 10)
	if err != nil || len(current) != 1 || current[0].Revision != 2 {
		t.Fatal("current ring catalog lost its head", err)
	}
	history, err := f.store.UpdateRingRevisions(ctx, "operator", f.identity.Scope, id, 2, 1)
	if err != nil || len(history) != 1 || history[0].Revision != 1 || !reflect.DeepEqual(history[0].Policy, updateTestPolicy()) {
		t.Fatal("history changed old intent", err)
	}
	for _, actor := range []string{"viewer", "foreign", "missing"} {
		if values, err := f.store.UpdateRings(ctx, actor, f.identity.Scope, 0, 10); err == nil || values != nil {
			t.Fatal("unauthorized ring catalog exposed")
		}
		if _, err := f.store.SaveUpdateRing(ctx, actor, f.identity.Scope, uuid.NewString(), uuid.NewString(), 0, "Synthetic ring", policy, true); err == nil {
			t.Fatal("unauthorized ring edit succeeded")
		}
	}
	if values, err := f.store.UpdateRingRevisions(ctx, "operator", access.Scope{TenantID: 1, SiteID: 12}, id, 0, 10); err == nil || values != nil {
		t.Fatal("history crossed scope")
	}
	stored, err := scanUpdateRing(f.store.db.QueryRow(`SELECT `+updateRingColumns+` FROM mdm_windows_update_ring_revisions WHERE ring_id=$1 AND revision=2`, id))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored.encrypted, []byte("Synthetic broad ring")) {
		t.Fatal("ring intent stored in plaintext")
	}
	changed := *stored
	changed.Revision = 1
	if err := f.store.openUpdateRing(&changed); err == nil {
		t.Fatal("ring ciphertext moved between revisions")
	}
	if _, err := f.store.db.Exec(`UPDATE mdm_windows_update_ring_revisions SET enabled=false WHERE ring_id=$1`, id); err == nil {
		t.Fatal("SQL rewrote ring history")
	}
	if _, err := f.store.db.Exec(`UPDATE mdm_windows_update_rings SET current_revision=1 WHERE id=$1`, id); err == nil {
		t.Fatal("SQL rolled back current revision")
	}
	if data, err := json.Marshal(next); err != nil || string(data) != "{}" {
		t.Fatal("generic serialization exposed a protected ring", err)
	}
}

func TestUpdateRingRolloutPinnedDeliveryAfterEditAndDisable(t *testing.T) {
	f := syncMLTestStore(t)
	ctx := context.Background()
	policy := updateTestFullPolicy()
	ring := updateTestRing(t, f, policy)
	key := uuid.NewString()
	cohort, err := f.store.AssignUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, key, []string{f.identity.DeviceID}, false, time.Hour)
	if err != nil || len(cohort.Runs) != 1 {
		t.Fatal("ring assignment failed", err)
	}
	if cohort.Runs[0].RingID != ring.RingID || cohort.Runs[0].RingRevision != 1 || cohort.Runs[0].RolloutID != cohort.ID {
		t.Fatal("run lost immutable ring provenance")
	}
	_, response := cspTestStart(t, f)
	if _, err := f.store.SaveUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, uuid.NewString(), 1, "Disabled revised ring", UpdatePolicy{QualityDeferralDays: updateTestInt(1)}, false); err != nil {
		t.Fatal(err)
	}
	for _, revision := range []int64{1, 2} {
		if value, err := f.store.AssignUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, revision, uuid.NewString(), []string{f.identity.DeviceID}, false, time.Hour); !errors.Is(err, ErrUpdateRingConflict) || value != nil {
			t.Fatal("obsolete or disabled ring admitted new apply", err)
		}
	}
	for step := 0; step < 7; step++ {
		request := syncMLTestWire(t, updateTestReply(syncMLTestParsed(t, response), policy, false, false))
		response, err = f.process(request)
		if err != nil {
			t.Fatal("ring edit changed admitted device intent", step, err)
		}
		if replay, err := f.process(request); err != nil || !bytes.Equal(replay, response) {
			t.Fatal("ring command replay changed", err)
		}
		f.store, err = NewStoreWithMasterKey(f.store.db, authorityTestMasterKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	if detail := updateTestRead(t, f, cohort.Runs[0].ID); detail.Phase != "verified" || len(detail.Outcomes) != 13 || !reflect.DeepEqual(detail.Policy, policy) {
		t.Fatal("pinned policy did not retain original results", detail.Phase)
	}
	retry, err := f.store.AssignUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, key, []string{f.identity.DeviceID}, false, time.Hour)
	if err != nil || !reflect.DeepEqual(retry, cohort) {
		t.Fatal("later edit or restart broke rollout retry", err)
	}
	observed, err := f.store.UpdateRolloutDetails(ctx, "operator", f.identity.Scope, cohort.ID)
	if err != nil || !reflect.DeepEqual(observed, cohort) {
		t.Fatal("rollout history lost its source", err)
	}
	if _, err := f.store.EnqueueUpdatePolicy(ctx, "operator", f.identity.Scope, f.identity.DeviceID, cohort.Runs[0].RequestKey, ring.Name, policy, false, time.Hour); !errors.Is(err, ErrCSPConflict) {
		t.Fatal("direct assignment borrowed a ring request identity", err)
	}
	removal, err := f.store.AssignUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), []string{f.identity.DeviceID}, true, time.Hour)
	if err != nil || removal.Runs[0].Mode != "remove" {
		t.Fatal("disabled ring blocked explicit historical removal", err)
	}
	if err := f.store.CancelUpdateRun(ctx, "operator", f.identity.Scope, f.identity.DeviceID, removal.Runs[0].ID); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRingCohortAtomicityAndExactMembership(t *testing.T) {
	f := syncMLTestStore(t)
	_, enrollment, _ := managementTestEnrollment(t, f.store, f.options)
	second := syncMLTestEnrolled(t, f.store, enrollment, f.options)
	ring := updateTestRing(t, f, updateTestPolicy())
	ctx := context.Background()
	targets := []string{f.identity.DeviceID, second.identity.DeviceID}
	slices.Sort(targets)
	// A missing last target must roll back even the first target's already inserted
	// run, commands and audits. The test operates solely on its isolated schema.
	invalid := append(slices.Clone(targets), "ffffffff-ffff-4fff-8fff-ffffffffffff")
	if value, err := f.store.AssignUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), invalid, false, time.Hour); err == nil || value != nil {
		t.Fatal("invalid cohort was partially admitted")
	}
	var runs, commands, rollouts int
	if err := f.store.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_windows_update_runs),(SELECT count(*) FROM mdm_windows_csp_commands),(SELECT count(*) FROM mdm_windows_update_rollouts)`).Scan(&runs, &commands, &rollouts); err != nil || runs != 0 || commands != 0 || rollouts != 0 {
		t.Fatal("failed cohort left partial work", err)
	}
	key := uuid.NewString()
	cohort, err := f.store.AssignUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, key, targets, false, time.Hour)
	if err != nil || len(cohort.Runs) != 2 {
		t.Fatal(err)
	}
	reversed := slices.Clone(targets)
	slices.Reverse(reversed)
	retry, err := f.store.AssignUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, key, reversed, false, time.Hour)
	if err != nil || !reflect.DeepEqual(retry, cohort) {
		t.Fatal("target order created new work", err)
	}
	for _, changed := range [][]string{targets[:1], append(slices.Clone(targets), uuid.NewString())} {
		if value, err := f.store.AssignUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, key, changed, false, time.Hour); !errors.Is(err, ErrUpdateRingConflict) || value != nil {
			t.Fatal("same request admitted a changed cohort", err)
		}
	}
	// Different reviewed cohorts may overlap and arrive in opposite caller order.
	// Both transactions must complete without lock inversion or lost runs.
	concurrent := make(chan error, 2)
	for _, members := range [][]string{targets, reversed} {
		go func(members []string) {
			_, err := f.store.AssignUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), members, false, time.Hour)
			concurrent <- err
		}(members)
	}
	for i := 0; i < 2; i++ {
		if err := <-concurrent; err != nil {
			t.Fatal("overlapping cohorts did not follow consistent device lock order", err)
		}
	}
	if err := f.store.permissions.ReplaceGrants(ctx, "admin", "operator", 1, []access.Grant{{Role: access.Operator, Scope: f.identity.Scope}}); err != nil {
		t.Fatal(err)
	}
	if value, err := f.store.AssignUpdateRing(ctx, "operator", f.identity.Scope, ring.RingID, 1, key, targets, false, time.Hour); !errors.Is(err, ErrUpdateRingConflict) || value != nil {
		t.Fatal("changed permission revision reused rollout authority", err)
	}
	_, reply := cspTestStart(t, f)
	if len(syncMLTestParsed(t, reply).Commands) != 1 {
		t.Fatal("old rollout creator authority was revived")
	}
	for _, run := range cohort.Runs {
		if run.DeviceID == f.identity.DeviceID && updateTestRead(t, f, run.ID).Phase != "canceled" {
			t.Fatal("old rollout creator authority was revived")
		}
	}
}

func FuzzUpdateRingTargets(f *testing.F) {
	f.Add([]byte(`["11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222"]`))
	f.Add([]byte(`["22222222-2222-4222-8222-222222222222","11111111-1111-4111-8111-111111111111"]`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		var devices []string
		if decodeSyncMLProtectedJSON(data, &devices) != nil {
			return
		}
		before := slices.Clone(devices)
		canonical, err := canonicalUpdateTargets(devices)
		if err != nil {
			return
		}
		if !slices.Equal(before, devices) || !slices.IsSorted(canonical) || len(canonical) == 0 || len(canonical) > 100 {
			t.Fatal("cohort normalization mutated input or broke its bounds")
		}
		encoded, err := json.Marshal(updateRolloutTargets{Version: 1, Devices: canonical})
		if err != nil || len(encoded) > 8192 {
			t.Fatal("bounded cohort exceeded protected storage")
		}
		var restored updateRolloutTargets
		if decodeSyncMLProtectedJSON(encoded, &restored) != nil || !slices.Equal(restored.Devices, canonical) {
			t.Fatal("protected cohort changed on restart")
		}
		slices.Reverse(devices)
		reordered, err := canonicalUpdateTargets(devices)
		if err != nil || !slices.Equal(canonical, reordered) {
			t.Fatal("input order changed reviewed membership")
		}
		keys := map[string]bool{}
		for _, device := range canonical {
			key := updateRolloutRequest("33333333-3333-4333-8333-333333333333", device)
			if !canonicalInvitationID(key) || keys[key] {
				t.Fatal("cohort targets shared a request identity")
			}
			keys[key] = true
		}
	})
}

func TestUpdateRingFullDeviceQueueRollsBackOtherTargets(t *testing.T) {
	f := syncMLTestStore(t)
	_, enrollment, _ := managementTestEnrollment(t, f.store, f.options)
	second := syncMLTestEnrolled(t, f.store, enrollment, f.options)
	last := f
	if last.identity.DeviceID < second.identity.DeviceID {
		last = second
	}
	for i := 0; i < 250; i++ {
		cspTestQueue(t, last, CSPCommandSpec{Kind: "Get", URI: "./Device/Vendor/MSFT/Synthetic/Value"})
	}
	ring := updateTestRing(t, f, updateTestFullPolicy())
	result, err := f.store.AssignUpdateRing(context.Background(), "operator", f.identity.Scope, ring.RingID, 1, uuid.NewString(), []string{f.identity.DeviceID, second.identity.DeviceID}, false, time.Hour)
	if !errors.Is(err, ErrCSPQueueFull) || result != nil {
		t.Fatal("full device queue admitted a partial ring cohort", err)
	}
	var runs, commands, rollouts int
	if err := f.store.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_windows_update_runs),(SELECT count(*) FROM mdm_windows_csp_commands),(SELECT count(*) FROM mdm_windows_update_rollouts)`).Scan(&runs, &commands, &rollouts); err != nil || runs != 0 || commands != 250 || rollouts != 0 {
		t.Fatal("late queue-capacity failure left another device's work committed", err)
	}
}
