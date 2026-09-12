package windows

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrUpdateSchedule = errors.New("invalid native Windows update schedule")
var ErrUpdateScheduleConflict = errors.New("native Windows update schedule revision or request conflict")
var ErrUpdateScheduleFull = errors.New("native Windows update schedule limit reached")

type UpdateSchedule struct {
	Group             *UpdateGroupSource `json:"-" xml:"-"`
	ID                string             `json:"-" xml:"-"`
	Scope             access.Scope       `json:"-" xml:"-"`
	RequestKey        string             `json:"-" xml:"-"`
	RingID            string             `json:"-" xml:"-"`
	RingRevision      int64              `json:"-" xml:"-"`
	CreatedBy         string             `json:"-" xml:"-"`
	CreatedByRevision int64              `json:"-" xml:"-"`
	Mode              string             `json:"-" xml:"-"`
	Lifetime          time.Duration      `json:"-" xml:"-"`
	CreatedAt         time.Time          `json:"-" xml:"-"`
	NotBefore         time.Time          `json:"-" xml:"-"`
	ExpiresAt         time.Time          `json:"-" xml:"-"`
	Targets           []string           `json:"-" xml:"-"`
	Phase             string             `json:"-" xml:"-"`
	Revision          int64              `json:"-" xml:"-"`
	UpdatedAt         time.Time          `json:"-" xml:"-"`
	NextAttemptAt     time.Time          `json:"-" xml:"-"`
	Attempts          int                `json:"-" xml:"-"`
	CompletedAt       *time.Time         `json:"-" xml:"-"`
	RolloutID         string             `json:"-" xml:"-"`
	Reason            string             `json:"-" xml:"-"`
}

type updateStoredSchedule struct {
	groupSources inventory.DeviceSources
	UpdateSchedule
	encryptedTargets []byte
	encryptedState   []byte
}

type updateScheduleState struct {
	Version int
	Reason  string
}

func (UpdateSchedule) String() string     { return "[protected Windows update schedule]" }
func (v UpdateSchedule) GoString() string { return v.String() }

const updateScheduleColumns = `id,tenant_id,site_id,request_key,ring_id,ring_revision,created_by,created_by_revision,mode,lifetime_seconds,created_at,not_before,expires_at,encrypted_targets,phase,revision,updated_at,next_attempt_at,attempts,completed_at,COALESCE(rollout_id::text,''),encrypted_state`

func scanUpdateSchedule(row cspScanner) (*updateStoredSchedule, error) {
	r := &updateStoredSchedule{}
	var seconds int64
	err := row.Scan(&r.ID, &r.Scope.TenantID, &r.Scope.SiteID, &r.RequestKey, &r.RingID, &r.RingRevision, &r.CreatedBy, &r.CreatedByRevision, &r.Mode, &seconds, &r.CreatedAt, &r.NotBefore, &r.ExpiresAt, &r.encryptedTargets, &r.Phase, &r.Revision, &r.UpdatedAt, &r.NextAttemptAt, &r.Attempts, &r.CompletedAt, &r.RolloutID, &r.encryptedState)
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

func updateSchedulePurpose(r *updateStoredSchedule) string {
	return fmt.Sprintf("openuem/windows/update-schedule/v1/%s/%d/%d/%s/%s/%d/%x/%d/%s/%d/%s/%s/%s", r.ID, r.Scope.TenantID, r.Scope.SiteID, r.RequestKey, r.RingID, r.RingRevision, sha256.Sum256([]byte(r.CreatedBy)), r.CreatedByRevision, r.Mode, int64(r.Lifetime/time.Second), r.CreatedAt.UTC().Format(time.RFC3339Nano), r.NotBefore.UTC().Format(time.RFC3339Nano), r.ExpiresAt.UTC().Format(time.RFC3339Nano))
}

func updateScheduleStatePurpose(r *updateStoredSchedule) string {
	return updateSchedulePurpose(r) + fmt.Sprintf("/state/%s/%d/%s/%s/%d/%s/%s", r.Phase, r.Revision, r.UpdatedAt.UTC().Format(time.RFC3339Nano), r.NextAttemptAt.UTC().Format(time.RFC3339Nano), r.Attempts, cspOptionalTime(r.CompletedAt), r.RolloutID)
}

func (s *Store) openUpdateSchedule(r *updateStoredSchedule) error {
	plain, err := s.secrets.openBounded(r.encryptedTargets, updateSchedulePurpose(r), 8192)
	if err != nil {
		return err
	}
	defer clear(plain)
	var targetSet updateRolloutTargets
	if decodeSyncMLProtectedJSON(plain, &targetSet) != nil || (targetSet.Version != 1 && targetSet.Version != 2) || (targetSet.Version == 1 && (targetSet.Group != nil || targetSet.Sources != nil)) || (targetSet.Version == 2 && (!validUpdateGroupSource(targetSet.Group.source()) || targetSet.Sources == nil || !targetSet.Sources.Windows)) {
		return ErrAuthoritySecret
	}
	targets, err := canonicalUpdateTargets(targetSet.Devices)
	if err != nil || !slices.Equal(targets, targetSet.Devices) {
		return ErrAuthoritySecret
	}
	stateBytes, err := s.secrets.openBounded(r.encryptedState, updateScheduleStatePurpose(r), 1024)
	if err != nil {
		return err
	}
	defer clear(stateBytes)
	var state updateScheduleState
	if decodeSyncMLProtectedJSON(stateBytes, &state) != nil || state.Version != 1 || !updateScheduleReason(state.Reason) {
		return ErrAuthoritySecret
	}
	r.Targets, r.Reason = targets, state.Reason
	r.Group = targetSet.Group.source()
	if targetSet.Sources != nil {
		r.groupSources = *targetSet.Sources
	}
	return nil
}

func updateScheduleReason(reason string) bool {
	switch reason {
	case "group_changed", "group_sources_changed", "", "device_queue_full", "authority_changed", "ring_assignment_conflict", "admission_deadline_expired", "device_unavailable", "scope_changed", "activation_window_expired", "canceled_by_operator":
		return true
	default:
		return false
	}
}

func (s *Store) sealUpdateScheduleState(r *updateStoredSchedule) error {
	if !updateScheduleReason(r.Reason) {
		return ErrAuthoritySecret
	}
	data, err := json.Marshal(updateScheduleState{Version: 1, Reason: r.Reason})
	if err != nil {
		return ErrAuthoritySecret
	}
	defer clear(data)
	r.encryptedState, err = s.secrets.sealBounded(data, updateScheduleStatePurpose(r), 1024)
	return err
}

func auditUpdateSchedule(ctx context.Context, tx *sql.Tx, r *updateStoredSchedule, actor, action string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_update_schedule_audit(schedule_id,tenant_id,site_id,actor,revision,action) VALUES($1,$2,$3,$4,$5,$6)`, r.ID, r.Scope.TenantID, r.Scope.SiteID, actor, r.Revision, action)
	return err
}

func (s *Store) writeUpdateSchedule(ctx context.Context, tx *sql.Tx, r *updateStoredSchedule, actor string) error {
	if err := s.sealUpdateScheduleState(r); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE mdm_windows_update_schedules SET phase=$2,revision=$3,updated_at=$4,next_attempt_at=$5,attempts=$6,completed_at=$7,rollout_id=NULLIF($8,'')::uuid,encrypted_state=$9 WHERE id=$1 AND revision=$3-1`, r.ID, r.Phase, r.Revision, r.UpdatedAt, r.NextAttemptAt, r.Attempts, r.CompletedAt, r.RolloutID, r.encryptedState)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrUpdateScheduleConflict
	}
	return auditUpdateSchedule(ctx, tx, r, actor, "schedule."+r.Phase)
}

func updateScheduleRolloutRequest(id string) string {
	return uuid.NewSHA1(uuid.MustParse(id), []byte("windows-update-activation")).String()
}

func (s *Store) validateUpdateRolloutSchedule(ctx context.Context, tx *sql.Tx, rollout *updateStoredRollout) error {
	if rollout.ScheduleID == "" {
		return nil
	}
	r, err := scanUpdateSchedule(tx.QueryRowContext(ctx, `SELECT `+updateScheduleColumns+` FROM mdm_windows_update_schedules WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR SHARE`, rollout.ScheduleID, rollout.Scope.TenantID, rollout.Scope.SiteID))
	if err != nil {
		return err
	}
	if err := s.openUpdateSchedule(r); err != nil {
		return err
	}
	if !sameUpdateGroupSource(r.Group, rollout.Group) || r.Phase != "activated" || r.RolloutID != rollout.ID || r.RingID != rollout.RingID || r.RingRevision != rollout.RingRevision || r.CreatedBy != rollout.CreatedBy || r.CreatedByRevision != rollout.CreatedByRevision || r.Mode != rollout.Mode || r.Lifetime != rollout.Lifetime || !slices.Equal(r.Targets, rollout.targets) || rollout.RequestKey != updateScheduleRolloutRequest(r.ID) || rollout.CreatedAt.Before(r.NotBefore) || rollout.CreatedAt.Before(r.CreatedAt) || r.CompletedAt == nil || rollout.CreatedAt.After(*r.CompletedAt) || !r.CompletedAt.Before(r.ExpiresAt) {
		return ErrAuthoritySecret
	}
	return nil
}

// ScheduleUpdateRing saves reviewed future intent without reserving device queue
// slots or changing device settings. Timing is an absolute instant, not local DST.
func (s *Store) ScheduleUpdateRing(ctx context.Context, actor string, scope access.Scope, ringID string, ringRevision int64, requestKey string, devices []string, remove bool, notBefore time.Time, activationWindow, runLifetime time.Duration) (*UpdateSchedule, error) {
	return s.scheduleUpdateRing(ctx, actor, scope, ringID, ringRevision, requestKey, devices, remove, notBefore, activationWindow, runLifetime, nil)
}

func (s *Store) scheduleUpdateRing(ctx context.Context, actor string, scope access.Scope, ringID string, ringRevision int64, requestKey string, devices []string, remove bool, notBefore time.Time, activationWindow, runLifetime time.Duration, group *updateGroupSelection) (*UpdateSchedule, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	targets, err := canonicalUpdateTargets(devices)
	if err != nil || !canonicalInvitationID(ringID) || !canonicalInvitationID(requestKey) || ringRevision < 1 || ringRevision > 1000000 || notBefore.IsZero() || notBefore.Nanosecond()%1000 != 0 || activationWindow < time.Minute || activationWindow > 7*24*time.Hour || activationWindow%time.Second != 0 || runLifetime < time.Minute || runLifetime > 7*24*time.Hour || runLifetime%time.Second != 0 {
		return nil, ErrUpdateSchedule
	}
	notBefore = notBefore.UTC()
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
	// Serialize admission counts and request identity in this site. Workers only
	// retire active entries, so they cannot race this cap upward.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,684627949))`, fmt.Sprintf("schedule-admission/%d/%d", scope.TenantID, scope.SiteID)); err != nil {
		return nil, err
	}
	var permissionRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM uem_access_revisions WHERE user_id=$1`, actor).Scan(&permissionRevision); err != nil {
		return nil, err
	}
	previous, err := scanUpdateSchedule(tx.QueryRowContext(ctx, `SELECT `+updateScheduleColumns+` FROM mdm_windows_update_schedules WHERE tenant_id=$1 AND site_id=$2 AND request_key=$3 FOR SHARE`, scope.TenantID, scope.SiteID, requestKey))
	if err == nil {
		if err := s.openUpdateSchedule(previous); err != nil {
			return nil, err
		}
		if !matchesUpdateGroupSelection(previous.Group, group) || previous.RingID != ringID || previous.RingRevision != ringRevision || previous.CreatedBy != actor || previous.CreatedByRevision != permissionRevision || previous.Mode != mode || previous.Lifetime != runLifetime || !previous.NotBefore.Equal(notBefore) || previous.ExpiresAt.Sub(previous.NotBefore) != activationWindow || !slices.Equal(previous.Targets, targets) {
			return nil, ErrUpdateScheduleConflict
		}
		if err := auditUpdateSchedule(ctx, tx, previous, actor, "schedule.replayed"); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &previous.UpdateSchedule, nil
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
	var groupSource *UpdateGroupSource
	if group != nil {
		if group.Sources != s.groupSources {
			return nil, ErrUpdateGroupConflict
		}
		preview, err := s.updateGroupPreviewTx(ctx, tx, actor, scope, group.Sources, group.ID, group.Revision)
		if err != nil {
			return nil, err
		}
		if !slices.Equal(preview.Targets, targets) {
			return nil, ErrUpdateGroupConflict
		}
		groupSource = &preview.Source
	}
	for _, device := range targets {
		if err := s.authorizeWindowsConsole(ctx, tx, actor, access.ManageUpdates, scope, device, false); err != nil {
			return nil, err
		}
		var revoked bool
		if err := tx.QueryRowContext(ctx, `SELECT revoked_at IS NOT NULL FROM mdm_windows_devices WHERE id=$1`, device).Scan(&revoked); err != nil {
			return nil, err
		}
		if revoked {
			return nil, ErrManagementIdentity
		}
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM mdm_windows_update_schedules WHERE tenant_id=$1 AND site_id=$2 AND phase IN ('scheduled','waiting')`, scope.TenantID, scope.SiteID).Scan(&count); err != nil {
		return nil, err
	}
	if count >= 256 {
		return nil, ErrUpdateScheduleFull
	}
	r := &updateStoredSchedule{UpdateSchedule: UpdateSchedule{Group: groupSource, ID: uuid.NewString(), Scope: scope, RequestKey: requestKey, RingID: ringID, RingRevision: ringRevision, CreatedBy: actor, CreatedByRevision: permissionRevision, Mode: mode, Lifetime: runLifetime, NotBefore: notBefore, ExpiresAt: notBefore.Add(activationWindow), Targets: targets, Phase: "scheduled", Revision: 1, NextAttemptAt: notBefore}}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&r.CreatedAt); err != nil {
		return nil, err
	}
	if notBefore.Before(r.CreatedAt.Add(-time.Minute)) || notBefore.After(r.CreatedAt.Add(90*24*time.Hour)) || !r.ExpiresAt.After(r.CreatedAt) {
		return nil, ErrUpdateSchedule
	}
	r.UpdatedAt = r.CreatedAt
	intent := updateRolloutTargets{Version: 1, Devices: targets}
	if group != nil {
		r.groupSources = group.Sources
		intent.Version = 2
		intent.Group = sealUpdateGroupSource(groupSource)
		intent.Sources = &r.groupSources
	}
	data, err := json.Marshal(intent)
	if err != nil {
		return nil, ErrUpdateSchedule
	}
	r.encryptedTargets, err = s.secrets.sealBounded(data, updateSchedulePurpose(r), 8192)
	clear(data)
	if err != nil {
		return nil, err
	}
	if err := s.sealUpdateScheduleState(r); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_update_schedules(id,tenant_id,site_id,request_key,ring_id,ring_revision,created_by,created_by_revision,mode,lifetime_seconds,created_at,not_before,expires_at,encrypted_targets,phase,revision,updated_at,next_attempt_at,attempts,encrypted_state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'scheduled',1,$11,$12,0,$15)`, r.ID, scope.TenantID, scope.SiteID, requestKey, ringID, ringRevision, actor, permissionRevision, mode, int64(runLifetime/time.Second), r.CreatedAt, r.NotBefore, r.ExpiresAt, r.encryptedTargets, r.encryptedState); err != nil {
		return nil, err
	}
	if err := auditUpdateSchedule(ctx, tx, r, actor, "schedule.created"); err != nil {
		return nil, err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	if now.Before(r.CreatedAt) || !now.Before(r.ExpiresAt) {
		return nil, ErrCSPDeadline
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &r.UpdateSchedule, nil
}
