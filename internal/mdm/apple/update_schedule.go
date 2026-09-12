package apple

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrUpdateSchedule = errors.New("invalid Apple update schedule")
var ErrUpdateScheduleFull = errors.New("Apple update schedule scope limit reached")
var ErrUpdateScheduleIntegrity = errors.New("Apple update schedule is unavailable")

// UpdateSchedule retains the reviewed source and exact native selection. Its
// activation window is an absolute instant; the plan's deadline is device-local.
type UpdateSchedule struct {
	ID            string                     `json:"-" xml:"-" yaml:"-"`
	Scope         Scope                      `json:"-" xml:"-" yaml:"-"`
	RequestKey    string                     `json:"-" xml:"-" yaml:"-"`
	Plan          UpdatePlan                 `json:"-" xml:"-" yaml:"-"`
	Group         ProfileGroupSource         `json:"-" xml:"-" yaml:"-"`
	Targets       []UpdatePlanGroupSelection `json:"-" xml:"-" yaml:"-"`
	Actor         string                     `json:"-" xml:"-" yaml:"-"`
	ActorRevision int64                      `json:"-" xml:"-" yaml:"-"`
	CreatedAt     time.Time                  `json:"-" xml:"-" yaml:"-"`
	NotBefore     time.Time                  `json:"-" xml:"-" yaml:"-"`
	ExpiresAt     time.Time                  `json:"-" xml:"-" yaml:"-"`
	Phase         string                     `json:"-" xml:"-" yaml:"-"`
	Revision      int                        `json:"-" xml:"-" yaml:"-"`
	UpdatedAt     time.Time                  `json:"-" xml:"-" yaml:"-"`
	NextAttemptAt time.Time                  `json:"-" xml:"-" yaml:"-"`
	Attempts      int                        `json:"-" xml:"-" yaml:"-"`
	CompletedAt   *time.Time                 `json:"-" xml:"-" yaml:"-"`
	AssignmentID  string                     `json:"-" xml:"-" yaml:"-"`
	Reason        string                     `json:"-" xml:"-" yaml:"-"`
}

func (UpdateSchedule) String() string     { return "[protected Apple update schedule]" }
func (v UpdateSchedule) GoString() string { return v.String() }

type updateStoredSchedule struct {
	UpdateSchedule
	sources                         inventory.DeviceSources
	activationKey                   string
	encryptedIntent, encryptedState []byte
}
type updateScheduleIntent struct {
	Version       int
	Plan          updatePlanWire
	PlanActor     string
	PlanCreatedAt time.Time
	Group         struct {
		ID       string
		Revision int
		Name     string
		Rule     inventory.DeviceGroupRule
	}
	Targets       []struct{ DeviceID, PolicyToken string }
	Sources       inventory.DeviceSources
	ActivationKey string
}
type updateScheduleState struct {
	Version int
	Reason  string
}

const updateScheduleColumns = `id,tenant_id,site_id,request_key,plan_id,plan_revision,actor,actor_revision,created_at,not_before,expires_at,CASE WHEN octet_length(encrypted_intent)<=32796 THEN encrypted_intent ELSE NULL END,phase,revision,updated_at,next_attempt_at,attempts,completed_at,COALESCE(assignment_id::text,''),CASE WHEN octet_length(encrypted_state)<=1052 THEN encrypted_state ELSE NULL END`

func updateSchedulePurpose(r *updateStoredSchedule) string {
	return fmt.Sprintf("openuem/apple/update-schedule/v1/%s/%d/%d/%s/%s/%d/%x/%d/%s/%s/%s", r.ID, r.Scope.TenantID, r.Scope.SiteID, r.RequestKey, r.Plan.ID, r.Plan.Revision, sha256.Sum256([]byte(r.Actor)), r.ActorRevision, r.CreatedAt.UTC().Format(time.RFC3339Nano), r.NotBefore.UTC().Format(time.RFC3339Nano), r.ExpiresAt.UTC().Format(time.RFC3339Nano))
}
func updateScheduleStatePurpose(r *updateStoredSchedule) string {
	completed := ""
	if r.CompletedAt != nil {
		completed = r.CompletedAt.UTC().Format(time.RFC3339Nano)
	}
	return updateSchedulePurpose(r) + fmt.Sprintf("/state/%s/%d/%s/%s/%d/%s/%s/%x", r.Phase, r.Revision, r.UpdatedAt.UTC().Format(time.RFC3339Nano), r.NextAttemptAt.UTC().Format(time.RFC3339Nano), r.Attempts, completed, r.AssignmentID, sha256.Sum256(r.encryptedIntent))
}
func decodeUpdateScheduleJSON(plain []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrUpdateScheduleIntegrity
	}
	return nil
}
func validUpdateScheduleReason(phase, reason string) bool {
	switch phase {
	case "scheduled", "activated":
		return reason == ""
	case "waiting":
		return reason == "temporarily_unavailable"
	case "blocked":
		switch reason {
		case "authority_changed", "scope_changed", "sources_changed", "review_changed", "source_unavailable", "activation_conflict":
			return true
		}
	case "expired":
		return reason == "activation_window_expired"
	case "canceled":
		return reason == "canceled_by_operator"
	}
	return false
}
func (s *Store) scanUpdateSchedule(row scanner) (*updateStoredSchedule, error) {
	r := &updateStoredSchedule{}
	if err := row.Scan(&r.ID, &r.Scope.TenantID, &r.Scope.SiteID, &r.RequestKey, &r.Plan.ID, &r.Plan.Revision, &r.Actor, &r.ActorRevision, &r.CreatedAt, &r.NotBefore, &r.ExpiresAt, &r.encryptedIntent, &r.Phase, &r.Revision, &r.UpdatedAt, &r.NextAttemptAt, &r.Attempts, &r.CompletedAt, &r.AssignmentID, &r.encryptedState); err != nil {
		return nil, notFound(err)
	}
	plain, err := s.secrets.open(r.encryptedIntent, updateSchedulePurpose(r))
	defer clear(plain)
	if err != nil || len(plain) > 32768 {
		return nil, ErrUpdateScheduleIntegrity
	}
	var wire updateScheduleIntent
	if decodeUpdateScheduleJSON(plain, &wire) != nil || wire.Version != 1 || wire.Plan.Version != 1 || !wire.Sources.Apple || !profileRevisionUUID(wire.ActivationKey) || wire.PlanCreatedAt.IsZero() || len(wire.PlanActor) < 1 || len(wire.PlanActor) > 255 || !profileRevisionUUID(wire.Group.ID) || wire.Group.Revision < 1 || wire.Group.Revision > 2147483647 || !(inventory.DeviceGroupDefinition{Name: wire.Group.Name, Rule: wire.Group.Rule}).Valid() {
		return nil, ErrUpdateScheduleIntegrity
	}
	d := wire.Plan
	r.Plan.Scope, r.Plan.Actor, r.Plan.CreatedAt = r.Scope, wire.PlanActor, wire.PlanCreatedAt
	r.Plan.Definition = UpdatePlanDefinition{Name: d.Name, Description: d.Description, Platform: d.Platform, TargetVersion: d.TargetVersion, TargetBuild: d.TargetBuild, Deadline: d.Deadline, DetailsURL: d.DetailsURL, Archived: d.Archived}
	if !r.Plan.Definition.Valid() || r.Plan.Definition.Archived {
		return nil, ErrUpdateScheduleIntegrity
	}
	r.Group = ProfileGroupSource{ID: wire.Group.ID, Revision: wire.Group.Revision, Name: wire.Group.Name, Rule: wire.Group.Rule}
	for _, target := range wire.Targets {
		r.Targets = append(r.Targets, UpdatePlanGroupSelection{DeviceID: target.DeviceID, PolicyToken: target.PolicyToken})
	}
	canonical, err := canonicalUpdateGroupSelection(r.Targets)
	if err != nil || !slices.Equal(canonical, r.Targets) {
		return nil, ErrUpdateScheduleIntegrity
	}
	stateBytes, err := s.secrets.open(r.encryptedState, updateScheduleStatePurpose(r))
	defer clear(stateBytes)
	var state updateScheduleState
	if err != nil || len(stateBytes) > 1024 || decodeUpdateScheduleJSON(stateBytes, &state) != nil || state.Version != 1 || !validUpdateScheduleReason(r.Phase, state.Reason) {
		return nil, ErrUpdateScheduleIntegrity
	}
	r.sources, r.activationKey, r.Reason = wire.Sources, wire.ActivationKey, state.Reason
	return r, nil
}
func (s *Store) sealUpdateScheduleIntent(r *updateStoredSchedule) error {
	d := r.Plan.Definition
	wire := updateScheduleIntent{Version: 1, Plan: updatePlanWire{Version: 1, Name: d.Name, Description: d.Description, Platform: d.Platform, TargetVersion: d.TargetVersion, TargetBuild: d.TargetBuild, Deadline: d.Deadline, DetailsURL: d.DetailsURL, Archived: d.Archived}, PlanActor: r.Plan.Actor, PlanCreatedAt: r.Plan.CreatedAt, Sources: r.sources, ActivationKey: r.activationKey}
	wire.Group.ID, wire.Group.Revision, wire.Group.Name, wire.Group.Rule = r.Group.ID, r.Group.Revision, r.Group.Name, r.Group.Rule
	for _, target := range r.Targets {
		wire.Targets = append(wire.Targets, struct{ DeviceID, PolicyToken string }{target.DeviceID, target.PolicyToken})
	}
	plain, err := json.Marshal(wire)
	defer clear(plain)
	if err != nil || len(plain) > 32768 {
		return ErrUpdateSchedule
	}
	r.encryptedIntent, err = s.secrets.seal(plain, updateSchedulePurpose(r))
	return err
}
func (s *Store) sealUpdateScheduleState(r *updateStoredSchedule) error {
	if !validUpdateScheduleReason(r.Phase, r.Reason) {
		return ErrUpdateScheduleIntegrity
	}
	plain, err := json.Marshal(updateScheduleState{Version: 1, Reason: r.Reason})
	defer clear(plain)
	if err != nil {
		return err
	}
	r.encryptedState, err = s.secrets.seal(plain, updateScheduleStatePurpose(r))
	return err
}
func (s *Store) insertUpdateSchedule(ctx context.Context, tx *sql.Tx, r *updateStoredSchedule) error {
	if err := s.sealUpdateScheduleIntent(r); err != nil {
		return err
	}
	if err := s.sealUpdateScheduleState(r); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_apple_update_schedules(id,tenant_id,site_id,request_key,plan_id,plan_revision,actor,actor_revision,created_at,not_before,expires_at,encrypted_intent,phase,revision,updated_at,next_attempt_at,attempts,encrypted_state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'scheduled',1,$9,$10,0,$13)`, r.ID, r.Scope.TenantID, r.Scope.SiteID, r.RequestKey, r.Plan.ID, r.Plan.Revision, r.Actor, r.ActorRevision, r.CreatedAt, r.NotBefore, r.ExpiresAt, r.encryptedIntent, r.encryptedState)
	return err
}
func (s *Store) writeUpdateSchedule(ctx context.Context, tx *sql.Tx, r *updateStoredSchedule, actor string) error {
	if err := s.sealUpdateScheduleState(r); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE mdm_apple_update_schedules SET phase=$2,revision=$3,updated_at=$4,next_attempt_at=$5,attempts=$6,completed_at=$7,assignment_id=NULLIF($8,'')::uuid,encrypted_state=$9 WHERE id=$1 AND revision=$3-1`, r.ID, r.Phase, r.Revision, r.UpdatedAt, r.NextAttemptAt, r.Attempts, r.CompletedAt, r.AssignmentID, r.encryptedState)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	return auditUpdatePlan(ctx, tx, r.Scope, actor, "schedule."+r.Phase, r.ID, r.Revision)
}

// ScheduleUpdatePlanFromGroup saves future intent without changing device
// policy or reserving queue slots. Exact retries return the original record.
func (s *Store) ScheduleUpdatePlanFromGroup(ctx context.Context, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, planID string, planRevision int, groupID string, groupRevision int, requestKey string, selection []UpdatePlanGroupSelection, notBefore time.Time, activationWindow time.Duration) (*UpdateSchedule, error) {
	targets, err := canonicalUpdateGroupSelection(selection)
	if err != nil || !profileRevisionUUID(planID) || planRevision < 1 || planRevision > 2147483647 || !profileRevisionUUID(groupID) || groupRevision < 1 || groupRevision > 2147483647 || !profileRevisionUUID(requestKey) || notBefore.IsZero() || notBefore.Nanosecond()%1000 != 0 || activationWindow < time.Minute || activationWindow > 7*24*time.Hour || activationWindow%time.Second != 0 {
		return nil, ErrUpdateSchedule
	}
	notBefore = notBefore.UTC()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = updatePlanAuthority(ctx, tx, permissions, actor, scope, access.ManageUpdates); err != nil {
		return nil, err
	}
	var actorRevision int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT revision FROM uem_access_revisions WHERE user_id=$1),0)`, actor).Scan(&actorRevision); err != nil {
		return nil, err
	}
	// Scope serialization bounds pending entries and protects client retry keys.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629907,hashtext($1))`, fmt.Sprintf("%d/%d", scope.TenantID, scope.SiteID)); err != nil {
		return nil, err
	}
	previous, err := s.scanUpdateSchedule(tx.QueryRowContext(ctx, `SELECT `+updateScheduleColumns+` FROM mdm_apple_update_schedules WHERE tenant_id=$1 AND site_id=$2 AND request_key=$3 FOR SHARE`, scope.TenantID, scope.SiteID, requestKey))
	if err == nil {
		if previous.Actor != actor || previous.ActorRevision != actorRevision || previous.Plan.ID != planID || previous.Plan.Revision != planRevision || previous.Group.ID != groupID || previous.Group.Revision != groupRevision || !slices.Equal(previous.Targets, targets) || !previous.NotBefore.Equal(notBefore) || previous.ExpiresAt.Sub(previous.NotBefore) != activationWindow {
			return nil, ErrConflict
		}
		if err = s.validateUpdateScheduleAssignment(ctx, tx, previous); err != nil {
			return nil, err
		}
		if err = auditUpdatePlan(ctx, tx, scope, actor, "schedule.replayed", previous.ID, previous.Revision); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return &previous.UpdateSchedule, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if !sources.Apple {
		return nil, ErrUpdateSchedule
	}
	preview, err := s.inspectUpdatePlanGroup(ctx, tx, actor, permissions, scope, sources, planID, planRevision, groupID, groupRevision, false)
	if err != nil {
		return nil, err
	}
	current := make([]UpdatePlanGroupSelection, len(preview.Targets))
	for i, target := range preview.Targets {
		current[i] = target.Selection
	}
	if !slices.Equal(targets, current) {
		return nil, ErrConflict
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_update_schedules WHERE tenant_id=$1 AND site_id=$2 AND phase IN ('scheduled','waiting')`, scope.TenantID, scope.SiteID).Scan(&count); err != nil {
		return nil, err
	}
	if count >= 256 {
		return nil, ErrUpdateScheduleFull
	}
	r := &updateStoredSchedule{UpdateSchedule: UpdateSchedule{ID: uuid.NewString(), Scope: scope, RequestKey: requestKey, Plan: preview.Plan, Group: ProfileGroupSource{ID: preview.Group.ID, Revision: preview.Group.Revision, Name: preview.Group.Name, Rule: preview.Group.Rule}, Targets: targets, Actor: actor, ActorRevision: actorRevision, NotBefore: notBefore, ExpiresAt: notBefore.Add(activationWindow), Phase: "scheduled", Revision: 1, NextAttemptAt: notBefore}, sources: sources, activationKey: uuid.NewString()}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&r.CreatedAt); err != nil {
		return nil, err
	}
	if notBefore.Before(r.CreatedAt.Add(-time.Minute)) || notBefore.After(r.CreatedAt.Add(90*24*time.Hour)) || !r.ExpiresAt.After(r.CreatedAt) {
		return nil, ErrUpdateSchedule
	}
	r.UpdatedAt = r.CreatedAt
	if err = s.insertUpdateSchedule(ctx, tx, r); err != nil {
		return nil, err
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "schedule.created", r.ID, r.Revision); err != nil {
		return nil, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	if now.Before(r.CreatedAt) || !now.Before(r.ExpiresAt) {
		return nil, ErrUpdateSchedule
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &r.UpdateSchedule, nil
}
