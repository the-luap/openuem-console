package windows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type UpdateRun struct {
	ID       string
	DeviceID string
	access.Scope
	RequestKey        string
	CreatedBy         string
	CreatedByRevision int64
	Mode              string
	CreatedAt         time.Time
	ExpiresAt         time.Time
	RingID            string
	RingRevision      int64
	RolloutID         string
}

type updateStoredRun struct {
	UpdateRun
	encrypted []byte
}

type updateIntent struct {
	Version int
	Name    string
	Policy  UpdatePolicy
}

func (UpdateRun) String() string        { return "[protected Windows update run]" }
func (v UpdateRun) GoString() string    { return v.String() }
func (updateIntent) String() string     { return "[protected Windows update intent]" }
func (v updateIntent) GoString() string { return v.String() }

const updateRunColumns = `id,device_id,tenant_id,site_id,request_key,created_by,created_by_revision,mode,created_at,expires_at,encrypted_intent,COALESCE(ring_id::text,''),COALESCE(ring_revision,0),COALESCE(rollout_id::text,'')`

func scanUpdateRun(row cspScanner) (*updateStoredRun, error) {
	run := &updateStoredRun{}
	err := row.Scan(&run.ID, &run.DeviceID, &run.TenantID, &run.SiteID, &run.RequestKey, &run.CreatedBy, &run.CreatedByRevision, &run.Mode, &run.CreatedAt, &run.ExpiresAt, &run.encrypted, &run.RingID, &run.RingRevision, &run.RolloutID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return run, nil
}

func updateRunPurpose(run *updateStoredRun) string {
	purpose := fmt.Sprintf("openuem/windows/update-intent/v1/%s/%s/%d/%d/%s/%x/%d/%s/%s/%s", run.ID, run.DeviceID, run.TenantID, run.SiteID, run.RequestKey, sha256.Sum256([]byte(run.CreatedBy)), run.CreatedByRevision, run.Mode, run.CreatedAt.UTC().Format(time.RFC3339Nano), run.ExpiresAt.UTC().Format(time.RFC3339Nano))
	if run.RingID != "" {
		purpose += fmt.Sprintf("/ring/%s/%d/rollout/%s", run.RingID, run.RingRevision, run.RolloutID)
	}
	return purpose
}

func (s *Store) openUpdateRun(run *updateStoredRun) (*updateIntent, error) {
	if (run.RingID == "" && (run.RingRevision != 0 || run.RolloutID != "")) || (run.RingID != "" && (!canonicalInvitationID(run.RingID) || run.RingRevision < 1 || !canonicalInvitationID(run.RolloutID))) {
		return nil, ErrAuthoritySecret
	}
	plain, err := s.secrets.openBounded(run.encrypted, updateRunPurpose(run), 8192)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var intent updateIntent
	if decodeSyncMLProtectedJSON(plain, &intent) != nil || (intent.Version != 1 && intent.Version != 2) || len(intent.Name) > 128 || !validEnrollmentUsername(intent.Name) || intent.Policy.Validate() != nil {
		return nil, ErrAuthoritySecret
	}
	return &intent, nil
}

// Version 2 fixes the partition in immutable intent. Never repartition existing
// runs based on today's response limit: stored trees and replays must stay exact.
const updateVerificationBatchSize = 3
const maxUpdateRunSteps = 7

func updateVerificationSettings(intent *updateIntent) ([][]updateSetting, error) {
	if intent == nil || (intent.Version != 1 && intent.Version != 2) {
		return nil, ErrUpdatePolicy
	}
	settings, err := intent.Policy.settings()
	if err != nil {
		return nil, err
	}
	if intent.Version == 1 {
		return [][]updateSetting{settings}, nil
	}
	batches := [][]updateSetting{}
	for len(settings) > 0 {
		count := min(updateVerificationBatchSize, len(settings))
		batches = append(batches, settings[:count])
		settings = settings[count:]
	}
	if len(batches)+2 > maxUpdateRunSteps {
		return nil, ErrUpdatePolicy
	}
	return batches, nil
}

func updateRunCommands(intent *updateIntent, remove bool) ([]CSPCommandSpec, error) {
	batches, err := updateVerificationSettings(intent)
	if err != nil {
		return nil, err
	}
	configure, verify, err := UpdatePolicyCommands(intent.Policy, remove)
	if err != nil {
		return nil, err
	}
	commands := []CSPCommandSpec{updatePlatformCommand(), configure}
	if intent.Version == 1 {
		return append(commands, verify), nil
	}
	for _, settings := range batches {
		batch := CSPCommandSpec{Kind: "Sequence"}
		for _, setting := range settings {
			batch.Commands = append(batch.Commands, CSPCommandSpec{Kind: "Get", URI: updateConfigRoot + setting.Name}, CSPCommandSpec{Kind: "Get", URI: updateResultRoot + setting.Name})
		}
		commands = append(commands, batch)
	}
	return commands, nil
}

func auditUpdateRun(ctx context.Context, tx *sql.Tx, run *updateStoredRun, actor, action string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_update_audit(run_id,actor,action) VALUES($1,$2,$3)`, run.ID, actor, action)
	return err
}

func checkUpdateRunDeadline(ctx context.Context, tx *sql.Tx, run *updateStoredRun) error {
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if now.Before(run.CreatedAt) || !now.Before(run.ExpiresAt) {
		return ErrCSPDeadline
	}
	return nil
}

// EnqueueUpdatePolicy admits an immutable, explicit device assignment. Only the
// generated trees can use ManageUpdates; callers cannot supply raw CSP.
func (s *Store) EnqueueUpdatePolicy(ctx context.Context, actor string, scope access.Scope, deviceID, requestKey, name string, policy UpdatePolicy, remove bool, validFor time.Duration) (*UpdateRun, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	run, err := s.enqueueUpdatePolicyTx(ctx, tx, actor, scope, deviceID, requestKey, name, policy, remove, validFor, nil)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return run, nil
}

// The caller owns the transaction so a reviewed ring cohort can be admitted all
// together. All normal device, authority, queue, audit and deadline checks remain.
func (s *Store) enqueueUpdatePolicyTx(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope, deviceID, requestKey, name string, policy UpdatePolicy, remove bool, validFor time.Duration, source *updateStoredRollout) (*UpdateRun, error) {
	if !canonicalInvitationID(requestKey) || len(name) > 128 || !validEnrollmentUsername(name) || validFor < time.Minute || validFor > 7*24*time.Hour || validFor%time.Second != 0 {
		return nil, ErrUpdatePolicy
	}
	intent := &updateIntent{Version: 2, Name: name, Policy: policy}
	commands, err := updateRunCommands(intent, remove)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(intent)
	if err != nil {
		return nil, ErrUpdatePolicy
	}
	defer clear(encoded)
	mode := "apply"
	if remove {
		mode = "remove"
	}
	if err := s.authorizeWindowsConsole(ctx, tx, actor, access.ManageUpdates, scope, deviceID, true); err != nil {
		return nil, err
	}
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM uem_access_revisions WHERE user_id=$1`, actor).Scan(&revision); err != nil {
		return nil, err
	}
	old, err := scanUpdateRun(tx.QueryRowContext(ctx, `SELECT `+updateRunColumns+` FROM mdm_windows_update_runs WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND request_key=$4 FOR SHARE`, deviceID, scope.TenantID, scope.SiteID, requestKey))
	if err == nil {
		previous, err := s.openUpdateRun(old)
		if err != nil {
			return nil, err
		}
		// Compare semantic intent across compiler upgrades without rewriting the
		// persisted version or any of its already queued/sent command trees.
		previous.Version = intent.Version
		previousBytes, err := json.Marshal(previous)
		if err != nil {
			return nil, ErrAuthoritySecret
		}
		defer clear(previousBytes)
		if !updateRunSourceMatches(old, source) || old.CreatedBy != actor || old.CreatedByRevision != revision || old.Mode != mode || old.ExpiresAt.Sub(old.CreatedAt) != validFor || !bytes.Equal(encoded, previousBytes) {
			return nil, ErrCSPConflict
		}
		if err := auditUpdateRun(ctx, tx, old, actor, "run.replayed"); err != nil {
			return nil, err
		}
		return &old.UpdateRun, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	var revoked bool
	if err := tx.QueryRowContext(ctx, `SELECT revoked_at IS NOT NULL FROM mdm_windows_devices WHERE id=$1`, deviceID).Scan(&revoked); err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrManagementIdentity
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM mdm_windows_csp_commands WHERE device_id=$1 AND phase IN ('queued','blocked','sent','unknown')`, deviceID).Scan(&count); err != nil {
		return nil, err
	}
	if count > 256-len(commands) {
		return nil, ErrCSPQueueFull
	}
	run := &updateStoredRun{UpdateRun: UpdateRun{ID: uuid.NewString(), DeviceID: deviceID, Scope: scope, RequestKey: requestKey, CreatedBy: actor, CreatedByRevision: revision, Mode: mode}}
	if source != nil {
		run.RingID, run.RingRevision, run.RolloutID = source.RingID, source.RingRevision, source.ID
	}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&run.CreatedAt); err != nil {
		return nil, err
	}
	if source != nil && run.CreatedAt.Before(source.CreatedAt) {
		return nil, ErrCSPDeadline
	}
	run.ExpiresAt = run.CreatedAt.Add(validFor)
	run.encrypted, err = s.secrets.sealBounded(encoded, updateRunPurpose(run), 8192)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_update_runs(id,device_id,tenant_id,site_id,request_key,created_by,created_by_revision,mode,created_at,expires_at,encrypted_intent,ring_id,ring_revision,rollout_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULLIF($12,'')::uuid,NULLIF($13,0),NULLIF($14,'')::uuid)`, run.ID, deviceID, scope.TenantID, scope.SiteID, requestKey, actor, revision, mode, run.CreatedAt, run.ExpiresAt, run.encrypted, run.RingID, run.RingRevision, run.RolloutID); err != nil {
		return nil, err
	}
	for step, spec := range commands {
		payload, user, err := encodeCSPRequest(spec)
		if err != nil || user {
			return nil, ErrUpdatePolicy
		}
		c := &cspStoredCommand{CSPCommand: CSPCommand{ID: uuid.NewString(), DeviceID: deviceID, Scope: scope, RequestKey: uuid.NewSHA1(uuid.MustParse(run.ID), []byte("windows-update-step/"+strconv.Itoa(step))).String(), CreatedBy: actor, CreatedByRevision: revision, Revision: 1, Phase: "queued", CreatedAt: run.CreatedAt, UpdatedAt: run.CreatedAt, ExpiresAt: run.ExpiresAt, UpdateRunID: run.ID, UpdateStep: step}}
		err = s.insertCSPCommand(ctx, tx, c, payload)
		clear(payload)
		if err != nil {
			return nil, err
		}
	}
	if err := auditUpdateRun(ctx, tx, run, actor, "run.created"); err != nil {
		return nil, err
	}
	if err := checkUpdateRunDeadline(ctx, tx, run); err != nil {
		return nil, err
	}
	return &run.UpdateRun, nil
}

func (s *Store) updateRunForCommand(ctx context.Context, tx *sql.Tx, c *cspStoredCommand) (*updateStoredRun, *updateIntent, error) {
	if !canonicalInvitationID(c.UpdateRunID) || c.UpdateStep < 0 || c.UpdateStep >= maxUpdateRunSteps {
		return nil, nil, ErrAuthoritySecret
	}
	run, err := scanUpdateRun(tx.QueryRowContext(ctx, `SELECT `+updateRunColumns+` FROM mdm_windows_update_runs WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR SHARE`, c.UpdateRunID, c.DeviceID, c.TenantID, c.SiteID))
	if err != nil {
		return nil, nil, err
	}
	if run.CreatedBy != c.CreatedBy || run.CreatedByRevision != c.CreatedByRevision || !run.CreatedAt.Equal(c.CreatedAt) || !run.ExpiresAt.Equal(c.ExpiresAt) {
		return nil, nil, ErrAuthoritySecret
	}
	intent, err := s.openUpdateRun(run)
	if err != nil {
		return nil, nil, err
	}
	if err := s.validateUpdateRunSource(ctx, tx, run, intent); err != nil {
		return nil, nil, err
	}
	commands, err := updateRunCommands(intent, run.Mode == "remove")
	if err != nil || c.UpdateStep >= len(commands) {
		return nil, nil, ErrAuthoritySecret
	}
	expected, _, err := encodeCSPRequest(commands[c.UpdateStep])
	if err != nil {
		return nil, nil, ErrAuthoritySecret
	}
	defer clear(expected)
	actual, _, err := s.openCSPRequest(c)
	if err != nil {
		return nil, nil, err
	}
	defer clear(actual)
	if !bytes.Equal(actual, expected) {
		return nil, nil, ErrAuthoritySecret
	}
	return run, intent, nil
}

func (s *Store) updateRunStep(ctx context.Context, tx *sql.Tx, run *updateStoredRun, step int) (*cspStoredCommand, *cspStoredResult, error) {
	c, err := scanCSPCommand(tx.QueryRowContext(ctx, `SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE update_run_id=$1 AND update_step=$2 AND device_id=$3 AND tenant_id=$4 AND site_id=$5 FOR SHARE`, run.ID, step, run.DeviceID, run.TenantID, run.SiteID))
	if err != nil {
		return nil, nil, err
	}
	if _, _, err := s.updateRunForCommand(ctx, tx, c); err != nil {
		return nil, nil, err
	}
	result, err := s.openCSPResult(c)
	return c, result, err
}

// A rejected prerequisite retires dependent undelivered work. It never makes a
// failed preflight or configuration look like a verified update policy.
func (s *Store) updateCommandEligibility(ctx context.Context, tx *sql.Tx, c *cspStoredCommand) (string, error) {
	if c.UpdateRunID == "" {
		return "", nil
	}
	run, intent, err := s.updateRunForCommand(ctx, tx, c)
	if err != nil {
		return "", err
	}
	if c.UpdateStep == 0 {
		return "", nil
	}
	previous, result, err := s.updateRunStep(ctx, tx, run, c.UpdateStep-1)
	if err != nil {
		return "", err
	}
	// A completed read-only batch can contain 404 or other failed Get statuses.
	// Preserve that evidence and collect the remaining settings. Mutations still
	// require a successful preflight, and verification a successful configuration.
	if previous.Phase != "acknowledged" && !(c.UpdateStep > 2 && previous.Phase == "failed") {
		return "update_prerequisite_not_acknowledged", nil
	}
	if c.UpdateStep > 2 {
		configuration, _, err := s.updateRunStep(ctx, tx, run, 1)
		if err != nil {
			return "", err
		}
		if configuration.Phase != "acknowledged" {
			return "update_prerequisite_not_acknowledged", nil
		}
	}
	if c.UpdateStep == 1 {
		platform := assessUpdatePlatform(intent.Policy, result.Exchange)
		if !platform.Compatible {
			return platform.Reason, nil
		}
		var now time.Time
		if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return "", err
		}
		if previous.CompletedAt == nil || previous.CompletedAt.After(now) || !now.Before(previous.CompletedAt.Add(15*time.Minute)) {
			return "update_platform_evidence_expired", nil
		}
	}
	return "", nil
}
