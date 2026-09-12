package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrUpdateEscalation = errors.New("invalid Apple update escalation request")
var ErrUpdateEscalationFull = errors.New("Apple update escalation monitoring limit reached")

type UpdateEscalationRequest struct {
	PlanID                string `json:"-" xml:"-" yaml:"-"`
	AssignmentID          string `json:"-" xml:"-" yaml:"-"`
	RequestKey            string `json:"-" xml:"-" yaml:"-"`
	ConfigurationRevision int    `json:"-" xml:"-" yaml:"-"`
	Enabled               bool   `json:"-" xml:"-" yaml:"-"`
	IncidentID            string `json:"-" xml:"-" yaml:"-"`
	Reason                string `json:"-" xml:"-" yaml:"-"`
}

func (UpdateEscalationRequest) String() string     { return "[protected Apple update escalation request]" }
func (r UpdateEscalationRequest) GoString() string { return r.String() }
func auditUpdateEscalation(ctx context.Context, tx *sql.Tx, scope Scope, actor, action, id string, revision int64) error {
	details, err := json.Marshal(map[string]any{"site_id": scope.SiteID, "revision": revision, "result": "success"})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,details) VALUES($1,$2,$3,$4,$5)`, scope.TenantID, actor, "apple.update.escalation."+action, id, details)
	return err
}
func (s *Store) persistUpdateEscalation(ctx context.Context, tx *sql.Tx, r *UpdateEscalation, previousRevision int64) error {
	config, state, err := s.sealUpdateEscalation(r)
	if err != nil {
		return err
	}
	args := []any{r.ID, r.Scope.TenantID, r.Scope.SiteID, r.PlanID, r.AssignmentID, r.ConfigurationRevision, r.Actor, r.ActorRevision, r.Enabled, r.CreatedAt, r.ConfiguredAt, r.ConfigurationEventID, config, r.StateRevision, r.Phase, r.Reason, r.UpdatedAt, r.CheckedAt, r.NextCheckAt, escalationNullableID(r.IncidentID), escalationNullableID(r.AcknowledgmentID), r.OpenCount, r.AwaitingCount, state}
	query := `INSERT INTO mdm_apple_update_escalations(id,tenant_id,site_id,plan_id,assignment_id,configuration_revision,actor,actor_revision,enabled,created_at,configured_at,configuration_event_id,encrypted_configuration,state_revision,phase,state_reason,updated_at,checked_at,next_check_at,incident_id,acknowledgment_id,open_count,awaiting_count,encrypted_state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)`
	if previousRevision > 0 {
		args = append(args, previousRevision)
		query = `UPDATE mdm_apple_update_escalations SET configuration_revision=$6,actor=$7,actor_revision=$8,enabled=$9,configured_at=$11,configuration_event_id=$12,encrypted_configuration=$13,state_revision=$14,phase=$15,state_reason=$16,updated_at=$17,checked_at=$18,next_check_at=$19,incident_id=$20,acknowledgment_id=$21,open_count=$22,awaiting_count=$23,encrypted_state=$24 WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4 AND assignment_id=$5 AND created_at=$10 AND state_revision=$25`
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrConflict
	}
	return nil
}
func updateEscalationClock(ctx context.Context, tx *sql.Tx, r *UpdateEscalation) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return now, err
	}
	if r != nil && (now.Before(r.UpdatedAt) || r.StateRevision == math.MaxInt64) {
		return now, ErrUpdateEscalationIntegrity
	}
	return now, nil
}
func (s *Store) escalationForAssignment(ctx context.Context, tx *sql.Tx, scope Scope, planID, assignmentID, lock string) (*UpdateEscalation, error) {
	r, err := s.scanUpdateEscalation(tx.QueryRowContext(ctx, `SELECT `+updateEscalationColumns+` FROM mdm_apple_update_escalations WHERE tenant_id=$1 AND site_id=$2 AND plan_id=$3 AND assignment_id=$4`+lock, scope.TenantID, scope.SiteID, planID, assignmentID))
	if err != nil {
		return nil, err
	}
	if err = s.validateUpdateEscalationSource(ctx, tx, r); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrUpdateEscalationIntegrity
		}
		return nil, err
	}
	if err = s.validateUpdateEscalationReferences(ctx, tx, r); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrUpdateEscalationIntegrity
		}
		return nil, err
	}
	return r, nil
}
func (s *Store) validateUpdateEscalationReferences(ctx context.Context, tx *sql.Tx, r *UpdateEscalation) error {
	config, err := s.scanUpdateEscalationEvent(tx.QueryRowContext(ctx, `SELECT `+updateEscalationEventColumns+` FROM mdm_apple_update_escalation_events WHERE id=$1 AND watch_id=$2 AND tenant_id=$3 AND site_id=$4 AND plan_id=$5 AND assignment_id=$6`, r.ConfigurationEventID, r.ID, r.Scope.TenantID, r.Scope.SiteID, r.PlanID, r.AssignmentID))
	if err != nil {
		return err
	}
	if config.Kind != "configured" || config.ConfigurationRevision != r.ConfigurationRevision || config.Actor != r.Actor || config.ActorRevision != r.ActorRevision || config.Enabled != r.Enabled || !config.CreatedAt.Equal(r.ConfiguredAt) || config.Revision > r.StateRevision {
		return ErrUpdateEscalationIntegrity
	}
	if err = s.validateUpdateEscalationEventSource(ctx, tx, config); err != nil {
		return err
	}
	if r.AcknowledgmentID != "" {
		ack, err := s.scanUpdateEscalationEvent(tx.QueryRowContext(ctx, `SELECT `+updateEscalationEventColumns+` FROM mdm_apple_update_escalation_events WHERE id=$1 AND watch_id=$2 AND tenant_id=$3 AND site_id=$4 AND plan_id=$5 AND assignment_id=$6`, r.AcknowledgmentID, r.ID, r.Scope.TenantID, r.Scope.SiteID, r.PlanID, r.AssignmentID))
		if err != nil {
			return err
		}
		if ack.Kind != "acknowledged" || ack.IncidentID != r.IncidentID || ack.ConfigurationRevision > r.ConfigurationRevision || ack.Revision > r.StateRevision || ack.CreatedAt.After(r.UpdatedAt) {
			return ErrUpdateEscalationIntegrity
		}
		if err = s.validateUpdateEscalationEventSource(ctx, tx, ack); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ConfigureUpdateEscalation(ctx context.Context, actor string, permissions *access.Store, scope Scope, request UpdateEscalationRequest) (*UpdateEscalationEvent, error) {
	return s.recordUpdateEscalationAction(ctx, actor, permissions, scope, request, "configured")
}
func (s *Store) AcknowledgeUpdateEscalation(ctx context.Context, actor string, permissions *access.Store, scope Scope, request UpdateEscalationRequest) (*UpdateEscalationEvent, error) {
	return s.recordUpdateEscalationAction(ctx, actor, permissions, scope, request, "acknowledged")
}
func (s *Store) recordUpdateEscalationAction(ctx context.Context, actor string, permissions *access.Store, scope Scope, q UpdateEscalationRequest, kind string) (*UpdateEscalationEvent, error) {
	if !profileRevisionUUID(q.PlanID) || !profileRevisionUUID(q.AssignmentID) || !profileRevisionUUID(q.RequestKey) || q.ConfigurationRevision < 0 || q.ConfigurationRevision > 2147483646 {
		return nil, ErrUpdateEscalation
	}
	if (kind == "configured" && (q.IncidentID != "" || q.Reason != "")) || (kind == "acknowledged" && (q.ConfigurationRevision < 1 || q.Enabled || !profileRevisionUUID(q.IncidentID) || !validUpdateExceptionReason(q.Reason))) {
		return nil, ErrUpdateEscalation
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = updateExceptionAuthority(ctx, tx, permissions, actor, scope); err != nil {
		return nil, err
	}
	var actorRevision int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT revision FROM uem_access_revisions WHERE user_id=$1),0)`, actor).Scan(&actorRevision); err != nil {
		return nil, err
	}
	// Serialize configuration admission and the site capacity, including retry keys.
	// Polls need only the row lock and never acquire this advisory lock.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629910,hashtext($1))`, fmt.Sprintf("%d/%d", scope.TenantID, scope.SiteID)); err != nil {
		return nil, err
	}
	previous, err := s.scanUpdateEscalationEvent(tx.QueryRowContext(ctx, `SELECT `+updateEscalationEventColumns+` FROM mdm_apple_update_escalation_events WHERE tenant_id=$1 AND site_id=$2 AND request_key=$3`, scope.TenantID, scope.SiteID, q.RequestKey))
	if err == nil {
		if previous.Kind != kind || previous.Actor != actor || previous.ActorRevision != actorRevision || previous.PlanID != q.PlanID || previous.AssignmentID != q.AssignmentID || previous.ExpectedRevision != q.ConfigurationRevision || (kind == "configured" && previous.Enabled != q.Enabled) || (kind == "acknowledged" && (previous.IncidentID != q.IncidentID || previous.Reason != q.Reason)) {
			return nil, ErrConflict
		}
		if err = s.validateUpdateEscalationEventSource(ctx, tx, previous); err != nil {
			return nil, err
		}
		if err = auditUpdateEscalation(ctx, tx, scope, actor, "replayed", previous.ID, previous.Revision); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return previous, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	r, err := s.escalationForAssignment(ctx, tx, scope, q.PlanID, q.AssignmentID, " FOR UPDATE")
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	// An absent watch is allowed only for the first enable. Source errors in an
	// existing watch must not be mistaken for permission to replace that watch.
	if errors.Is(err, ErrNotFound) {
		var exists bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_update_escalations WHERE tenant_id=$1 AND site_id=$2 AND assignment_id=$3)`, scope.TenantID, scope.SiteID, q.AssignmentID).Scan(&exists); err != nil {
			return nil, err
		}
		if exists || kind != "configured" || q.ConfigurationRevision != 0 || !q.Enabled {
			return nil, ErrConflict
		}
		original, sourceErr := s.scanUpdateGroupAssignment(tx.QueryRowContext(ctx, `SELECT `+updateGroupColumns+` FROM mdm_apple_update_group_assignments WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4`, q.AssignmentID, scope.TenantID, scope.SiteID, q.PlanID))
		if sourceErr != nil {
			return nil, sourceErr
		}
		r = &UpdateEscalation{ID: uuid.NewString(), Scope: scope, PlanID: q.PlanID, AssignmentID: q.AssignmentID, Assignment: original}
		for _, c := range original.Commands {
			r.original = append(r.original, c.Selection.DeviceID)
		}
	}
	if r.ConfigurationRevision != q.ConfigurationRevision {
		return nil, ErrConflict
	}
	if kind == "acknowledged" && (r.IncidentID != q.IncidentID || r.AcknowledgmentID != "") {
		return nil, ErrConflict
	}
	if kind == "configured" && q.Enabled && !r.Enabled {
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_update_escalations WHERE tenant_id=$1 AND site_id=$2 AND enabled`, scope.TenantID, scope.SiteID).Scan(&count); err != nil {
			return nil, err
		}
		if count >= 256 {
			return nil, ErrUpdateEscalationFull
		}
	}
	now, err := updateEscalationClock(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	previousRevision := r.StateRevision
	r.StateRevision++
	r.UpdatedAt = now
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	if kind == "configured" {
		r.ConfigurationRevision++
		r.ConfiguredAt = now
		r.ConfigurationEventID = uuid.NewString()
		r.Actor = actor
		r.ActorRevision = actorRevision
		r.Enabled = q.Enabled
		r.Reason = ""
		r.Phase = "paused"
		r.NextCheckAt = nil
		if r.Enabled {
			r.Phase = "watching"
			r.NextCheckAt = &now
		}
	} else if r.NextCheckAt != nil && r.NextCheckAt.Before(now) {
		r.NextCheckAt = &now
	}
	e := escalationEvent(r, kind, actor, actorRevision)
	e.RequestKey = q.RequestKey
	e.ExpectedRevision = q.ConfigurationRevision
	e.Reason = q.Reason
	if kind == "configured" {
		e.ID = r.ConfigurationEventID
	} else {
		r.AcknowledgmentID = e.ID
	}
	if err = s.validateUpdateEscalationSource(ctx, tx, r); err != nil {
		return nil, err
	}
	if err = s.persistUpdateEscalation(ctx, tx, r, previousRevision); err != nil {
		return nil, err
	}
	if err = s.insertUpdateEscalationEvent(ctx, tx, e); err != nil {
		return nil, err
	}
	if err = auditUpdateEscalation(ctx, tx, scope, actor, kind, e.ID, e.Revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return e, nil
}
