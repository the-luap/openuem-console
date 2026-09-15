package windows

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
)

func updateTestFullPolicy() UpdatePolicy {
	return UpdatePolicy{
		QualityDeferralDays: updateTestInt(30), FeatureDeferralDays: updateTestInt(365),
		QualityDeadlineDays: updateTestInt(30), FeatureDeadlineDays: updateTestInt(30),
		QualityGraceDays: updateTestInt(7), FeatureGraceDays: updateTestInt(7),
		QualityNoAutoReboot: updateTestBool(true), FeatureNoAutoReboot: updateTestBool(false),
		ActiveHoursStart: updateTestInt(22), ActiveHoursEnd: updateTestInt(16), ActiveHoursMaximum: updateTestInt(18),
		NotificationLevel: updateTestInt(2), ExcludeDrivers: updateTestBool(true),
	}
}

func updateTestReadError(reply *SyncMLMessage, uri, status string) {
	ref := ""
	filtered := reply.Commands[:0]
	for _, command := range reply.Commands {
		if command.Kind == "Results" && command.Items[0].Source.URI == uri {
			ref = command.CommandRef
			continue
		}
		filtered = append(filtered, command)
	}
	reply.Commands = filtered
	for i := range reply.Commands {
		command := &reply.Commands[i]
		if command.Kind == "Status" && command.CommandRef == ref && ref != "" {
			command.Data.Text = status
		}
	}
}

func TestUpdateVersionedBatchesKeepConfigurationAndReadPairs(t *testing.T) {
	for _, policy := range []UpdatePolicy{updateTestFullPolicy(), updateTestPolicy(), {QualityDeferralDays: updateTestInt(0)}} {
		for _, remove := range []bool{false, true} {
			legacy, err := updateRunCommands(&updateIntent{Version: 1, Policy: policy}, remove)
			if err != nil || len(legacy) != 3 {
				t.Fatal("legacy run changed", err)
			}
			current, err := updateRunCommands(&updateIntent{Version: 2, Policy: policy}, remove)
			if err != nil || len(current) > 7 || !reflect.DeepEqual(current[:2], legacy[:2]) {
				t.Fatal("batching changed Atomic configuration or preflight", err)
			}
			reads := []CSPCommandSpec{}
			for _, batch := range current[2:] {
				if batch.Kind != "Sequence" || len(batch.Commands) < 2 || len(batch.Commands) > 6 || len(batch.Commands)%2 != 0 {
					t.Fatal("batch broke its bounded Config/Result pairs")
				}
				reads = append(reads, batch.Commands...)
			}
			if !reflect.DeepEqual(reads, legacy[2].Commands) {
				t.Fatal("batch partition dropped, reordered or added settings")
			}
		}
	}
	for _, intent := range []*updateIntent{nil, {Version: 0, Policy: updateTestPolicy()}, {Version: 3, Policy: updateTestPolicy()}} {
		if _, err := updateRunCommands(intent, false); !errors.Is(err, ErrUpdatePolicy) {
			t.Fatal("unknown compiler version accepted", err)
		}
	}
}

func TestUpdateBatchedOutcomeWindowAndPartialEvidence(t *testing.T) {
	intent := &updateIntent{Version: 2, Policy: updateTestFullPolicy()}
	batches, err := updateVerificationSettings(intent)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	detail := &UpdateRunDetail{Run: UpdateRun{Mode: "apply"}, Steps: make([]CSPCommand, len(batches)+2)}
	results := make([]*cspStoredResult, len(detail.Steps))
	for step := range detail.Steps {
		delivered, completed := start.Add(time.Duration(step)*time.Second), start.Add(time.Duration(step)*time.Second+time.Millisecond)
		detail.Steps[step] = CSPCommand{Phase: "acknowledged", DeliveredAt: &delivered, CompletedAt: &completed}
		results[step] = &cspStoredResult{Version: 1}
		if step < 2 {
			continue
		}
		state := &cspSessionCommand{Operations: []cspOperationResult{{Kind: "Sequence", Status: 200}}}
		for _, setting := range batches[step-2] {
			for _, root := range []string{updateConfigRoot, updateResultRoot} {
				state.Operations = append(state.Operations, cspOperationResult{Kind: "Get", URI: root + setting.Name, Status: 200, HasResult: true, Format: "int", Text: strconv.Itoa(setting.Value)})
			}
		}
		results[step].Exchange = state
	}
	results[0].Exchange = updateTestPlatformState("10.0.26100.1", "Enterprise", "9", "Windows 11 Enterprise")
	if err := updateRunOutcome(detail, intent, results); err != nil || detail.Phase != "verified" || len(detail.Outcomes) != 13 {
		t.Fatal("old completed evidence lost its historical result", detail.Phase, err)
	}
	for _, outcome := range detail.Outcomes {
		if outcome.EvidenceReceivedAt == nil || outcome.EvidenceReceivedAt.Before(start) {
			t.Fatal("per-batch evidence receipt time missing")
		}
	}
	last := len(detail.Steps) - 1
	for _, phase := range []string{"queued", "blocked", "sent", "canceled", "unknown", "abandoned", "expired"} {
		detail.Steps[last].Phase = phase
		if err := updateRunOutcome(detail, intent, results); err != nil || len(detail.Outcomes) != 12 || detail.Phase == "verified" {
			t.Fatal("unfinished final batch fabricated success or erased evidence", phase, detail.Phase, err)
		}
	}
	detail.Steps[last].Phase = "acknowledged"
	boundary := detail.Steps[2].DeliveredAt.Add(15 * time.Minute)
	detail.Steps[last].CompletedAt = &boundary
	if err := updateRunOutcome(detail, intent, results); err != nil || detail.Phase != "verification_stale" || len(detail.Outcomes) != 13 {
		t.Fatal("widely separated observations appeared verified", detail.Phase, err)
	}
	boundary = boundary.Add(-time.Nanosecond)
	if err := updateRunOutcome(detail, intent, results); err != nil || detail.Phase != "verified" {
		t.Fatal("valid observation window rejected", detail.Phase, err)
	}
	detail.Steps[3].DeliveredAt = detail.Steps[2].DeliveredAt
	if err := updateRunOutcome(detail, intent, results); err != nil || detail.Phase != "verification_stale" {
		t.Fatal("out-of-order observations appeared verified", detail.Phase, err)
	}
}

// Create a genuine version-1 run under the old step constraint, using the owned
// synthetic database and the original encrypted representation. No history or
// command trigger is bypassed to construct this upgrade fixture.
func updateTestLegacyRun(t *testing.T, f syncMLStoreFixture, policy UpdatePolicy) *updateStoredRun {
	t.Helper()
	ctx := context.Background()
	tx, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	run := &updateStoredRun{UpdateRun: UpdateRun{ID: uuid.NewString(), DeviceID: f.identity.DeviceID, Scope: f.identity.Scope, RequestKey: uuid.NewString(), CreatedBy: "operator", Mode: "apply"}}
	if err := tx.QueryRow(`SELECT revision,clock_timestamp() FROM uem_access_revisions WHERE user_id='operator'`).Scan(&run.CreatedByRevision, &run.CreatedAt); err != nil {
		t.Fatal(err)
	}
	run.ExpiresAt = run.CreatedAt.Add(time.Hour)
	intent := &updateIntent{Version: 1, Name: "Legacy synthetic ring", Policy: policy}
	plain, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	run.encrypted, err = f.store.secrets.sealBounded(plain, updateRunPurpose(run), 8192)
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO mdm_windows_update_runs(id,device_id,tenant_id,site_id,request_key,created_by,created_by_revision,mode,created_at,expires_at,encrypted_intent) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, run.ID, run.DeviceID, run.TenantID, run.SiteID, run.RequestKey, run.CreatedBy, run.CreatedByRevision, run.Mode, run.CreatedAt, run.ExpiresAt, run.encrypted); err != nil {
		t.Fatal(err)
	}
	commands, err := updateRunCommands(intent, false)
	if err != nil {
		t.Fatal(err)
	}
	for step, spec := range commands {
		payload, _, err := encodeCSPRequest(spec)
		if err != nil {
			t.Fatal(err)
		}
		c := &cspStoredCommand{CSPCommand: CSPCommand{ID: uuid.NewString(), DeviceID: run.DeviceID, Scope: run.Scope, RequestKey: uuid.NewSHA1(uuid.MustParse(run.ID), []byte("windows-update-step/"+strconv.Itoa(step))).String(), CreatedBy: run.CreatedBy, CreatedByRevision: run.CreatedByRevision, Revision: 1, Phase: "queued", CreatedAt: run.CreatedAt, UpdatedAt: run.CreatedAt, ExpiresAt: run.ExpiresAt, UpdateRunID: run.ID, UpdateStep: step}}
		if err := f.store.insertCSPCommand(ctx, tx, c, payload); err != nil {
			t.Fatal(err)
		}
		clear(payload)
	}
	if err := auditUpdateRun(ctx, tx, run, "operator", "run.created"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return run
}

func TestUpdateBatchMigrationKeepsLegacyQueuedAndSentRuns(t *testing.T) {
	for _, sent := range []bool{false, true} {
		t.Run(strconv.FormatBool(sent), func(t *testing.T) {
			f := syncMLTestStore(t)
			if _, err := f.store.db.Exec(`ALTER TABLE mdm_windows_csp_commands DROP CONSTRAINT mdm_windows_csp_update_identity; ALTER TABLE mdm_windows_csp_commands ADD CONSTRAINT mdm_windows_csp_update_identity CHECK ((update_run_id IS NULL AND update_step IS NULL) OR (update_run_id IS NOT NULL AND update_step IS NOT NULL AND update_step BETWEEN 0 AND 2 AND NOT user_target)); DELETE FROM mdm_windows_migrations WHERE name='migrations/007_update_verification_batches.sql'`); err != nil {
				t.Fatal(err)
			}
			policy := updateTestPolicy()
			run := updateTestLegacyRun(t, f, policy)
			var request, response []byte
			if sent {
				request, response = cspTestStart(t, f)
			}
			for n := 0; n < 2; n++ {
				if err := f.store.Migrate(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			retry, err := f.store.EnqueueUpdatePolicy(context.Background(), "operator", f.identity.Scope, f.identity.DeviceID, run.RequestKey, "Legacy synthetic ring", policy, false, time.Hour)
			if err != nil || retry.ID != run.ID {
				t.Fatal("compiler upgrade broke idempotent old intent", err)
			}
			persisted, err := scanUpdateRun(f.store.db.QueryRow(`SELECT `+updateRunColumns+` FROM mdm_windows_update_runs WHERE id=$1`, run.ID))
			if err != nil || !bytes.Equal(persisted.encrypted, run.encrypted) {
				t.Fatal("migration or retry rewrote immutable intent", err)
			}
			if sent {
				if replay, err := f.process(request); err != nil || !bytes.Equal(replay, response) {
					t.Fatal("migration changed sent packet replay", err)
				}
			} else {
				_, response = cspTestStart(t, f)
			}
			for step := 0; step < 3; step++ {
				response, err = f.process(syncMLTestWire(t, updateTestReply(syncMLTestParsed(t, response), policy, false, false)))
				if err != nil {
					t.Fatal("legacy run could not finish after upgrade", step, err)
				}
			}
			detail := updateTestRead(t, f, run.ID)
			if detail.Phase != "verified" || len(detail.Steps) != 3 || len(detail.Outcomes) != 7 {
				t.Fatal("legacy result acquired new compiler semantics", detail.Phase)
			}
			current := updateTestQueue(t, f, updateTestFullPolicy(), false)
			if len(updateTestRead(t, f, current.ID).Steps) != 7 {
				t.Fatal("migration did not admit new batched runs")
			}
		})
	}
}

func TestUpdateBatchQueueCapacityReservesEveryStep(t *testing.T) {
	f := syncMLTestStore(t)
	var last *CSPCommand
	for n := 0; n < 250; n++ {
		last = cspTestQueue(t, f, CSPCommandSpec{Kind: "Get", URI: "./Device/Vendor/MSFT/Synthetic/Value"})
	}
	ctx := context.Background()
	key := uuid.NewString()
	queue := func() (*UpdateRun, error) {
		return f.store.EnqueueUpdatePolicy(ctx, "operator", f.identity.Scope, f.identity.DeviceID, key, "Synthetic full ring", updateTestFullPolicy(), false, time.Hour)
	}
	if run, err := queue(); !errors.Is(err, ErrCSPQueueFull) || run != nil {
		t.Fatal("seven-step run overfilled the device queue", err)
	}
	var count int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM mdm_windows_update_runs`).Scan(&count); err != nil || count != 0 {
		t.Fatal("capacity rejection left an orphan update run", err)
	}
	if err := f.store.CancelCSPCommand(ctx, "admin", f.identity.Scope, f.identity.DeviceID, last.ID, last.Revision); err != nil {
		t.Fatal(err)
	}
	run, err := queue()
	if err != nil {
		t.Fatal("exactly fitting run rejected", err)
	}
	if err := f.store.db.QueryRow(`SELECT count(*) FROM mdm_windows_csp_commands WHERE phase IN ('queued','blocked','sent','unknown')`).Scan(&count); err != nil || count != 256 {
		t.Fatal("typed queue reservation did not match compiled steps", count, err)
	}
	if replay, err := queue(); err != nil || replay.ID != run.ID {
		t.Fatal("full queue prevented an idempotent retry", err)
	}
}

func TestUpdateBatchCancellationPreservesCompletedEvidence(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(strconv.FormatBool(blocked), func(t *testing.T) {
			f := syncMLTestStore(t)
			policy := updateTestFullPolicy()
			run := updateTestQueue(t, f, policy, false)
			_, response := cspTestStart(t, f)
			for step := 0; step < 3; step++ {
				reply := updateTestReply(syncMLTestParsed(t, response), policy, false, false)
				if step == 2 && blocked {
					maximum := uint64(1000)
					reply.Header.Meta = &SyncMLMeta{MaxMessageSize: &maximum}
				}
				var err error
				response, err = f.process(syncMLTestWire(t, reply))
				if err != nil {
					t.Fatal(err)
				}
			}
			before := updateTestRead(t, f, run.ID)
			err := f.store.CancelUpdateRun(context.Background(), "operator", f.identity.Scope, f.identity.DeviceID, run.ID)
			if blocked && err != nil || !blocked && !errors.Is(err, ErrCSPAlreadySent) {
				t.Fatal("cancellation did not respect active batch delivery", err)
			}
			after := updateTestRead(t, f, run.ID)
			if len(after.Outcomes) != 3 || !reflect.DeepEqual(before.Outcomes, after.Outcomes) {
				t.Fatal("cancellation erased completed read evidence")
			}
			for step := 3; step < 7; step++ {
				if blocked && after.Steps[step].Phase != "canceled" || !blocked && !reflect.DeepEqual(before.Steps[step], after.Steps[step]) {
					t.Fatal("cancellation partially changed remaining stages", step)
				}
			}
			if blocked && after.Phase != "canceled" || !blocked && after.Phase != "verification_pending" {
				t.Fatal("partial evidence appeared to complete the run", after.Phase)
			}
		})
	}
}

func TestUpdateBatchProofRejectsReassignedReadsAndOutOfRangeSteps(t *testing.T) {
	f := syncMLTestStore(t)
	run := updateTestQueue(t, f, updateTestFullPolicy(), false)
	c, err := scanCSPCommand(f.store.db.QueryRow(`SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE update_run_id=$1 AND update_step=6`, run.ID))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	commands, err := updateRunCommands(&updateIntent{Version: 2, Policy: updateTestFullPolicy()}, false)
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := encodeCSPRequest(commands[2])
	if err != nil {
		t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{4}, 32)
	c.digest = cspRequestDigest(salt, payload)
	plain, err := json.Marshal(cspProtectedRequest{Version: 1, Salt: salt, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	c.request, err = f.store.secrets.sealBounded(plain, cspPurpose("request", c), maxCSPProtectedBytes)
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.updateRunForCommand(context.Background(), tx, c); !errors.Is(err, ErrAuthoritySecret) {
		t.Fatal("correctly encrypted first-batch reads became final-batch evidence", err)
	}
	for _, step := range []int{-1, 7} {
		c.UpdateStep = step
		if _, _, err := f.store.updateRunForCommand(context.Background(), tx, c); !errors.Is(err, ErrAuthoritySecret) {
			t.Fatal("out-of-range step bypassed compiler proof", err)
		}
	}
	tx.Rollback()
	short := updateTestQueue(t, f, UpdatePolicy{QualityDeferralDays: updateTestInt(0)}, false)
	c, err = scanCSPCommand(f.store.db.QueryRow(`SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE update_run_id=$1 AND update_step=2`, short.ID))
	if err != nil {
		t.Fatal(err)
	}
	tx, err = f.store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	c.UpdateStep = 3
	if _, _, err := f.store.updateRunForCommand(context.Background(), tx, c); !errors.Is(err, ErrAuthoritySecret) {
		t.Fatal("globally valid step exceeded this run's compiler bounds", err)
	}
}
