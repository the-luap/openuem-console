package windows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type UpdateRollout struct {
	ID                string        `json:"-" xml:"-"`
	Scope             access.Scope  `json:"-" xml:"-"`
	RequestKey        string        `json:"-" xml:"-"`
	RingID            string        `json:"-" xml:"-"`
	RingRevision      int64         `json:"-" xml:"-"`
	CreatedBy         string        `json:"-" xml:"-"`
	CreatedByRevision int64         `json:"-" xml:"-"`
	Mode              string        `json:"-" xml:"-"`
	Lifetime          time.Duration `json:"-" xml:"-"`
	CreatedAt         time.Time     `json:"-" xml:"-"`
	Runs              []UpdateRun   `json:"-" xml:"-"`
}

type updateStoredRollout struct {
	UpdateRollout
	encrypted []byte
	targets   []string
}

type updateRolloutTargets struct {
	Version int
	Devices []string
}

func (UpdateRollout) String() string            { return "[protected Windows update rollout]" }
func (v UpdateRollout) GoString() string        { return v.String() }
func (updateRolloutTargets) String() string     { return "[protected Windows update targets]" }
func (v updateRolloutTargets) GoString() string { return v.String() }

const updateRolloutColumns = `id,tenant_id,site_id,request_key,ring_id,ring_revision,created_by,created_by_revision,mode,lifetime_seconds,created_at,encrypted_targets`

func scanUpdateRollout(row cspScanner) (*updateStoredRollout, error) {
	r := &updateStoredRollout{}
	var seconds int64
	err := row.Scan(&r.ID, &r.Scope.TenantID, &r.Scope.SiteID, &r.RequestKey, &r.RingID, &r.RingRevision, &r.CreatedBy, &r.CreatedByRevision, &r.Mode, &seconds, &r.CreatedAt, &r.encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if seconds < 60 || seconds > 604800 {
		return nil, ErrAuthoritySecret
	}
	r.Lifetime = time.Duration(seconds) * time.Second
	return r, nil
}

func canonicalUpdateTargets(devices []string) ([]string, error) {
	if len(devices) < 1 || len(devices) > 100 {
		return nil, ErrUpdateRing
	}
	targets := slices.Clone(devices)
	slices.Sort(targets)
	for i, id := range targets {
		if !canonicalInvitationID(id) || i > 0 && targets[i-1] == id {
			return nil, ErrUpdateRing
		}
	}
	return targets, nil
}

func updateRolloutPurpose(r *updateStoredRollout) string {
	return fmt.Sprintf("openuem/windows/update-rollout/v1/%s/%d/%d/%s/%s/%d/%x/%d/%s/%d/%s", r.ID, r.Scope.TenantID, r.Scope.SiteID, r.RequestKey, r.RingID, r.RingRevision, sha256.Sum256([]byte(r.CreatedBy)), r.CreatedByRevision, r.Mode, int64(r.Lifetime/time.Second), r.CreatedAt.UTC().Format(time.RFC3339Nano))
}

func (s *Store) openUpdateRollout(r *updateStoredRollout) error {
	plain, err := s.secrets.openBounded(r.encrypted, updateRolloutPurpose(r), 8192)
	if err != nil {
		return err
	}
	defer clear(plain)
	var decoded updateRolloutTargets
	if decodeSyncMLProtectedJSON(plain, &decoded) != nil || decoded.Version != 1 {
		return ErrAuthoritySecret
	}
	targets, err := canonicalUpdateTargets(decoded.Devices)
	if err != nil || !slices.Equal(targets, decoded.Devices) {
		return ErrAuthoritySecret
	}
	r.targets = targets
	return nil
}

func updateRolloutRequest(id, device string) string {
	return uuid.NewSHA1(uuid.MustParse(id), []byte("windows-update-device/"+device)).String()
}

func updateRunSourceMatches(run *updateStoredRun, source *updateStoredRollout) bool {
	if source == nil {
		return run.RingID == "" && run.RingRevision == 0 && run.RolloutID == ""
	}
	return run.RingID == source.RingID && run.RingRevision == source.RingRevision && run.RolloutID == source.ID
}

// The encrypted source snapshot, not today's ring head, authorizes the exact
// generated policy. Current command-creator permissions are checked separately.
func (s *Store) validateUpdateRunSource(ctx context.Context, tx *sql.Tx, run *updateStoredRun, intent *updateIntent) error {
	if run.RingID == "" {
		return nil
	}
	source, err := scanUpdateRollout(tx.QueryRowContext(ctx, `SELECT `+updateRolloutColumns+` FROM mdm_windows_update_rollouts WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR SHARE`, run.RolloutID, run.TenantID, run.SiteID))
	if err != nil {
		return err
	}
	if err := s.openUpdateRollout(source); err != nil {
		return err
	}
	if !updateRunSourceMatches(run, source) || run.CreatedBy != source.CreatedBy || run.CreatedByRevision != source.CreatedByRevision || run.Mode != source.Mode || run.ExpiresAt.Sub(run.CreatedAt) != source.Lifetime || run.CreatedAt.Before(source.CreatedAt) || !slices.Contains(source.targets, run.DeviceID) || run.RequestKey != updateRolloutRequest(source.ID, run.DeviceID) {
		return ErrAuthoritySecret
	}
	ring, err := s.updateRingRevision(ctx, tx, run.Scope, source.RingID, source.RingRevision)
	if err != nil {
		return err
	}
	expected, err := canonicalUpdatePolicy(ring.Policy)
	if err != nil {
		return ErrAuthoritySecret
	}
	defer clear(expected)
	actual, err := canonicalUpdatePolicy(intent.Policy)
	if err != nil {
		return ErrAuthoritySecret
	}
	defer clear(actual)
	if intent.Name != ring.Name || !bytes.Equal(expected, actual) || run.Mode == "apply" && !ring.Enabled {
		return ErrAuthoritySecret
	}
	return nil
}

// AssignUpdateRing atomically captures an explicit reviewed cohort and creates
// one normal, immutable update run per device. It does not contact any endpoint.
// Apply requires the current enabled revision. Removal may reference historical
// revisions, allowing source-specific cleanup after a ring was disabled/changed.
func (s *Store) AssignUpdateRing(ctx context.Context, actor string, scope access.Scope, ringID string, ringRevision int64, requestKey string, devices []string, remove bool, validFor time.Duration) (*UpdateRollout, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	targets, err := canonicalUpdateTargets(devices)
	if err != nil || !canonicalInvitationID(ringID) || !canonicalInvitationID(requestKey) || ringRevision < 1 || ringRevision > 1000000 || validFor < time.Minute || validFor > 7*24*time.Hour || validFor%time.Second != 0 {
		return nil, ErrUpdateRing
	}
	mode := "apply"
	if remove {
		mode = "remove"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeUpdateRing(ctx, tx, actor, scope); err != nil {
		return nil, err
	}
	// Serialize the same scoped request across rings, without serializing all
	// rollouts. Sorted device locks below also order overlapping cohorts.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,684627948))`, fmt.Sprintf("%d/%d/%s", scope.TenantID, scope.SiteID, requestKey)); err != nil {
		return nil, err
	}
	var permissionRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM uem_access_revisions WHERE user_id=$1`, actor).Scan(&permissionRevision); err != nil {
		return nil, err
	}
	previous, err := scanUpdateRollout(tx.QueryRowContext(ctx, `SELECT `+updateRolloutColumns+` FROM mdm_windows_update_rollouts WHERE tenant_id=$1 AND site_id=$2 AND request_key=$3 FOR SHARE`, scope.TenantID, scope.SiteID, requestKey))
	if err == nil {
		if err := s.openUpdateRollout(previous); err != nil {
			return nil, err
		}
		if previous.RingID != ringID || previous.RingRevision != ringRevision || previous.CreatedBy != actor || previous.CreatedByRevision != permissionRevision || previous.Mode != mode || previous.Lifetime != validFor || !slices.Equal(previous.targets, targets) {
			return nil, ErrUpdateRingConflict
		}
		if err := s.loadUpdateRolloutRuns(ctx, tx, actor, previous); err != nil {
			return nil, err
		}
		ring, err := s.updateRingRevision(ctx, tx, scope, ringID, ringRevision)
		if err != nil {
			return nil, err
		}
		if err := auditUpdateRing(ctx, tx, ring, actor, "rollout.replayed", previous.ID); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &previous.UpdateRollout, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	var current int64
	if err := tx.QueryRowContext(ctx, `SELECT current_revision FROM mdm_windows_update_rings WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR SHARE`, ringID, scope.TenantID, scope.SiteID).Scan(&current); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	ring, err := s.updateRingRevision(ctx, tx, scope, ringID, ringRevision)
	if err != nil {
		return nil, err
	}
	if !remove && (current != ringRevision || !ring.Enabled) {
		return nil, ErrUpdateRingConflict
	}
	rollout := &updateStoredRollout{UpdateRollout: UpdateRollout{ID: uuid.NewString(), Scope: scope, RequestKey: requestKey, RingID: ringID, RingRevision: ringRevision, CreatedBy: actor, CreatedByRevision: permissionRevision, Mode: mode, Lifetime: validFor, Runs: []UpdateRun{}}, targets: targets}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&rollout.CreatedAt); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(updateRolloutTargets{Version: 1, Devices: targets})
	if err != nil {
		return nil, ErrUpdateRing
	}
	rollout.encrypted, err = s.secrets.sealBounded(plain, updateRolloutPurpose(rollout), 8192)
	clear(plain)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_update_rollouts(id,tenant_id,site_id,request_key,ring_id,ring_revision,created_by,created_by_revision,mode,lifetime_seconds,created_at,encrypted_targets) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, rollout.ID, scope.TenantID, scope.SiteID, requestKey, ringID, ringRevision, actor, permissionRevision, mode, int64(validFor/time.Second), rollout.CreatedAt, rollout.encrypted); err != nil {
		return nil, err
	}
	for _, device := range targets {
		run, err := s.enqueueUpdatePolicyTx(ctx, tx, actor, scope, device, updateRolloutRequest(rollout.ID, device), ring.Name, ring.Policy, remove, validFor, rollout)
		if err != nil {
			return nil, err
		}
		rollout.Runs = append(rollout.Runs, *run)
	}
	if err := auditUpdateRing(ctx, tx, ring, actor, "rollout.created", rollout.ID); err != nil {
		return nil, err
	}
	// The cohort audit can wait. Recheck every run's original deadline afterward.
	for _, run := range rollout.Runs {
		if err := checkUpdateRunDeadline(ctx, tx, &updateStoredRun{UpdateRun: run}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &rollout.UpdateRollout, nil
}

func (s *Store) loadUpdateRolloutRuns(ctx context.Context, tx *sql.Tx, actor string, rollout *updateStoredRollout) error {
	rows, err := tx.QueryContext(ctx, `SELECT `+updateRunColumns+` FROM mdm_windows_update_runs WHERE rollout_id=$1 AND tenant_id=$2 AND site_id=$3 ORDER BY device_id LIMIT 101 FOR SHARE`, rollout.ID, rollout.Scope.TenantID, rollout.Scope.SiteID)
	if err != nil {
		return err
	}
	runs := []*updateStoredRun{}
	for rows.Next() {
		run, err := scanUpdateRun(rows)
		if err != nil {
			rows.Close()
			return err
		}
		runs = append(runs, run)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(runs) != len(rollout.targets) {
		return ErrAuthoritySecret
	}
	rollout.Runs = []UpdateRun{}
	for i, run := range runs {
		if run.DeviceID != rollout.targets[i] {
			return ErrAuthoritySecret
		}
		if err := s.authorizeWindowsConsole(ctx, tx, actor, access.ManageUpdates, rollout.Scope, run.DeviceID, false); err != nil {
			return err
		}
		intent, err := s.openUpdateRun(run)
		if err != nil {
			return err
		}
		if err := s.validateUpdateRunSource(ctx, tx, run, intent); err != nil {
			return err
		}
		rollout.Runs = append(rollout.Runs, run.UpdateRun)
	}
	return nil
}

func (s *Store) UpdateRolloutDetails(ctx context.Context, actor string, scope access.Scope, id string) (*UpdateRollout, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !canonicalInvitationID(id) {
		return nil, ErrUpdateRing
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeUpdateRing(ctx, tx, actor, scope); err != nil {
		return nil, err
	}
	rollout, err := scanUpdateRollout(tx.QueryRowContext(ctx, `SELECT `+updateRolloutColumns+` FROM mdm_windows_update_rollouts WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR SHARE`, id, scope.TenantID, scope.SiteID))
	if err != nil {
		return nil, err
	}
	if err := s.openUpdateRollout(rollout); err != nil {
		return nil, err
	}
	if err := s.loadUpdateRolloutRuns(ctx, tx, actor, rollout); err != nil {
		return nil, err
	}
	ring, err := s.updateRingRevision(ctx, tx, scope, rollout.RingID, rollout.RingRevision)
	if err != nil {
		return nil, err
	}
	if err := auditUpdateRing(ctx, tx, ring, actor, "rollout.read", rollout.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &rollout.UpdateRollout, nil
}
