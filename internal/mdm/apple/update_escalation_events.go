package apple

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
)

// Events retain the decision evidence at the time of an action. They never
// substitute current device metadata for an original cohort's history.
type UpdateEscalationEvent struct {
	ID                    string                     `json:"-" xml:"-" yaml:"-"`
	WatchID               string                     `json:"-" xml:"-" yaml:"-"`
	Scope                 Scope                      `json:"-" xml:"-" yaml:"-"`
	PlanID                string                     `json:"-" xml:"-" yaml:"-"`
	AssignmentID          string                     `json:"-" xml:"-" yaml:"-"`
	Revision              int64                      `json:"-" xml:"-" yaml:"-"`
	ConfigurationRevision int                        `json:"-" xml:"-" yaml:"-"`
	Kind                  string                     `json:"-" xml:"-" yaml:"-"`
	Actor                 string                     `json:"-" xml:"-" yaml:"-"`
	ActorRevision         int64                      `json:"-" xml:"-" yaml:"-"`
	RequestKey            string                     `json:"-" xml:"-" yaml:"-"`
	IncidentID            string                     `json:"-" xml:"-" yaml:"-"`
	CreatedAt             time.Time                  `json:"-" xml:"-" yaml:"-"`
	WatchCreatedAt        time.Time                  `json:"-" xml:"-" yaml:"-"`
	Enabled               bool                       `json:"-" xml:"-" yaml:"-"`
	Phase                 string                     `json:"-" xml:"-" yaml:"-"`
	StateReason           string                     `json:"-" xml:"-" yaml:"-"`
	ExpectedRevision      int                        `json:"-" xml:"-" yaml:"-"`
	Reason                string                     `json:"-" xml:"-" yaml:"-"`
	OpenTargets           []string                   `json:"-" xml:"-" yaml:"-"`
	AwaitingTargets       []string                   `json:"-" xml:"-" yaml:"-"`
	Snapshot              *UpdateEscalationSnapshot  `json:"-" xml:"-" yaml:"-"`
	Assignment            *UpdatePlanGroupAssignment `json:"-" xml:"-" yaml:"-"`
	original              []string
}

func (UpdateEscalationEvent) String() string     { return "[protected Apple update escalation event]" }
func (e UpdateEscalationEvent) GoString() string { return e.String() }

type updateEscalationEventWire struct {
	Version                  int
	WatchCreatedAt           time.Time
	Enabled                  bool
	Phase, StateReason       string
	ExpectedRevision         int
	Reason                   string
	Original, Open, Awaiting []string
	Snapshot                 *updateEscalationSnapshotWire
}

const updateEscalationEventColumns = `id,watch_id,tenant_id,site_id,plan_id,assignment_id,revision,configuration_revision,CASE WHEN octet_length(kind)<=16 THEN kind ELSE NULL END,CASE WHEN octet_length(actor)<=255 THEN actor ELSE NULL END,actor_revision,request_key,incident_id,created_at,CASE WHEN octet_length(encrypted_event)<=131100 THEN encrypted_event ELSE NULL END`

func updateEscalationEventPurpose(e *UpdateEscalationEvent) string {
	return fmt.Sprintf("openuem/apple/update-escalation/event/v1/%s/%s/%d/%d/%s/%s/%d/%d/%s/%x/%d/%s/%s/%s", e.ID, e.WatchID, e.Scope.TenantID, e.Scope.SiteID, e.PlanID, e.AssignmentID, e.Revision, e.ConfigurationRevision, e.Kind, sha256.Sum256([]byte(e.Actor)), e.ActorRevision, e.RequestKey, e.IncidentID, e.CreatedAt.UTC().Format(time.RFC3339Nano))
}
func validateUpdateEscalationEvent(e *UpdateEscalationEvent) error {
	if !profileRevisionUUID(e.ID) || !profileRevisionUUID(e.WatchID) || !profileRevisionUUID(e.PlanID) || !profileRevisionUUID(e.AssignmentID) || e.Scope.TenantID < 1 || e.Scope.SiteID < 1 || e.ConfigurationRevision < 1 || e.ConfigurationRevision > 2147483647 || e.Revision < int64(e.ConfigurationRevision) || len(e.Actor) < 1 || len(e.Actor) > 255 || e.ActorRevision < 0 || e.WatchCreatedAt.IsZero() || e.CreatedAt.Before(e.WatchCreatedAt) || !validEscalationTargetIDs(e.original) || len(e.original) == 0 || !validEscalationTargetIDs(e.OpenTargets) || !validEscalationTargetIDs(e.AwaitingTargets) {
		return ErrUpdateEscalationIntegrity
	}
	switch e.Phase {
	case "watching":
		if !e.Enabled || e.StateReason != "" {
			return ErrUpdateEscalationIntegrity
		}
	case "paused":
		if e.Enabled || e.StateReason != "" {
			return ErrUpdateEscalationIntegrity
		}
	case "blocked":
		if !e.Enabled || (e.StateReason != "authority_changed" && e.StateReason != "source_unavailable") {
			return ErrUpdateEscalationIntegrity
		}
	default:
		return ErrUpdateEscalationIntegrity
	}
	if (len(e.OpenTargets) == 0 && e.IncidentID != "") || (len(e.OpenTargets) > 0 && !profileRevisionUUID(e.IncidentID)) {
		return ErrUpdateEscalationIntegrity
	}
	switch e.Kind {
	case "configured":
		if !profileRevisionUUID(e.RequestKey) || e.ExpectedRevision != e.ConfigurationRevision-1 || e.Reason != "" || e.Phase == "blocked" {
			return ErrUpdateEscalationIntegrity
		}
	case "acknowledged":
		if !profileRevisionUUID(e.RequestKey) || e.ExpectedRevision != e.ConfigurationRevision || !validUpdateExceptionReason(e.Reason) || e.IncidentID == "" {
			return ErrUpdateEscalationIntegrity
		}
	case "attention", "updated", "cleared", "blocked":
		if e.RequestKey != "" || e.ExpectedRevision != 0 || e.Reason != "" || (e.Kind == "blocked") != (e.Phase == "blocked") || (e.Kind == "cleared" && len(e.OpenTargets) != 0) || (e.Kind == "attention" && len(e.OpenTargets) == 0) {
			return ErrUpdateEscalationIntegrity
		}
	default:
		return ErrUpdateEscalationIntegrity
	}
	if e.Snapshot == nil {
		if len(e.OpenTargets) != 0 || len(e.AwaitingTargets) != 0 || (e.Kind != "configured" && e.Kind != "blocked") {
			return ErrUpdateEscalationIntegrity
		}
		return nil
	}
	if e.Snapshot.AssessedAt.Before(e.WatchCreatedAt) || e.Snapshot.AssessedAt.After(e.CreatedAt) {
		return ErrUpdateEscalationIntegrity
	}
	if _, err := decodeEscalationSnapshot(escalationSnapshotWire(e.Snapshot), e.original); err != nil {
		return err
	}
	decisions := make([]UpdateEscalationDecision, 0, len(e.Snapshot.Devices))
	for _, d := range e.Snapshot.Devices {
		decisions = append(decisions, d.Decision)
	}
	open, awaiting, _, err := mergeUpdateEscalationTargets(e.OpenTargets, decisions)
	if err != nil || !slices.Equal(open, e.OpenTargets) || !slices.Equal(awaiting, e.AwaitingTargets) {
		return ErrUpdateEscalationIntegrity
	}
	return nil
}
func escalationEvent(r *UpdateEscalation, kind, actor string, actorRevision int64) *UpdateEscalationEvent {
	return &UpdateEscalationEvent{ID: uuid.NewString(), WatchID: r.ID, Scope: r.Scope, PlanID: r.PlanID, AssignmentID: r.AssignmentID, Revision: r.StateRevision, ConfigurationRevision: r.ConfigurationRevision, Kind: kind, Actor: actor, ActorRevision: actorRevision, IncidentID: r.IncidentID, CreatedAt: r.UpdatedAt, WatchCreatedAt: r.CreatedAt, Enabled: r.Enabled, Phase: r.Phase, StateReason: r.Reason, OpenTargets: slices.Clone(r.OpenTargets), AwaitingTargets: slices.Clone(r.AwaitingTargets), Snapshot: r.Snapshot, Assignment: r.Assignment, original: slices.Clone(r.original)}
}
func (s *Store) insertUpdateEscalationEvent(ctx context.Context, tx *sql.Tx, e *UpdateEscalationEvent) error {
	if err := validateUpdateEscalationEvent(e); err != nil {
		return err
	}
	wire := updateEscalationEventWire{1, e.WatchCreatedAt, e.Enabled, e.Phase, e.StateReason, e.ExpectedRevision, e.Reason, e.original, e.OpenTargets, e.AwaitingTargets, escalationSnapshotWire(e.Snapshot)}
	encrypted, err := s.sealUpdateEscalationWire(wire, updateEscalationEventPurpose(e), 131072)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_update_escalation_events(id,watch_id,tenant_id,site_id,plan_id,assignment_id,revision,configuration_revision,kind,actor,actor_revision,request_key,incident_id,created_at,encrypted_event) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, e.ID, e.WatchID, e.Scope.TenantID, e.Scope.SiteID, e.PlanID, e.AssignmentID, e.Revision, e.ConfigurationRevision, e.Kind, e.Actor, e.ActorRevision, escalationNullableID(e.RequestKey), escalationNullableID(e.IncidentID), e.CreatedAt, encrypted)
	return err
}
func escalationNullableID(id string) any {
	if id == "" {
		return nil
	}
	return id
}
func (s *Store) scanUpdateEscalationEvent(row scanner) (*UpdateEscalationEvent, error) {
	e := &UpdateEscalationEvent{}
	var key, incident sql.NullString
	var encrypted []byte
	if err := row.Scan(&e.ID, &e.WatchID, &e.Scope.TenantID, &e.Scope.SiteID, &e.PlanID, &e.AssignmentID, &e.Revision, &e.ConfigurationRevision, &e.Kind, &e.Actor, &e.ActorRevision, &key, &incident, &e.CreatedAt, &encrypted); err != nil {
		return nil, notFound(err)
	}
	e.RequestKey, e.IncidentID = key.String, incident.String
	var w updateEscalationEventWire
	if err := s.openUpdateEscalationWire(encrypted, updateEscalationEventPurpose(e), 131072, &w); err != nil {
		return nil, err
	}
	if w.Version != 1 {
		return nil, ErrUpdateEscalationIntegrity
	}
	e.WatchCreatedAt, e.Enabled, e.Phase, e.StateReason, e.ExpectedRevision, e.Reason, e.original, e.OpenTargets, e.AwaitingTargets = w.WatchCreatedAt, w.Enabled, w.Phase, w.StateReason, w.ExpectedRevision, w.Reason, w.Original, w.Open, w.Awaiting
	var err error
	if e.Snapshot, err = decodeEscalationSnapshot(w.Snapshot, e.original); err != nil {
		return nil, err
	}
	if err = validateUpdateEscalationEvent(e); err != nil {
		return nil, err
	}
	return e, nil
}
func (s *Store) validateUpdateEscalationEventSource(ctx context.Context, tx *sql.Tx, e *UpdateEscalationEvent) error {
	r := &UpdateEscalation{Scope: e.Scope, PlanID: e.PlanID, AssignmentID: e.AssignmentID, CreatedAt: e.WatchCreatedAt, Snapshot: e.Snapshot, original: e.original}
	if err := s.validateUpdateEscalationSource(ctx, tx, r); err != nil {
		return err
	}
	e.Assignment = r.Assignment
	return nil
}
