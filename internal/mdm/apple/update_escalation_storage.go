package apple

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"
)

type UpdateEscalation struct {
	ID                    string                     `json:"-" xml:"-" yaml:"-"`
	Scope                 Scope                      `json:"-" xml:"-" yaml:"-"`
	PlanID                string                     `json:"-" xml:"-" yaml:"-"`
	AssignmentID          string                     `json:"-" xml:"-" yaml:"-"`
	ConfigurationRevision int                        `json:"-" xml:"-" yaml:"-"`
	Actor                 string                     `json:"-" xml:"-" yaml:"-"`
	ActorRevision         int64                      `json:"-" xml:"-" yaml:"-"`
	Enabled               bool                       `json:"-" xml:"-" yaml:"-"`
	CreatedAt             time.Time                  `json:"-" xml:"-" yaml:"-"`
	ConfiguredAt          time.Time                  `json:"-" xml:"-" yaml:"-"`
	ConfigurationEventID  string                     `json:"-" xml:"-" yaml:"-"`
	StateRevision         int64                      `json:"-" xml:"-" yaml:"-"`
	Phase                 string                     `json:"-" xml:"-" yaml:"-"`
	Reason                string                     `json:"-" xml:"-" yaml:"-"`
	UpdatedAt             time.Time                  `json:"-" xml:"-" yaml:"-"`
	CheckedAt             *time.Time                 `json:"-" xml:"-" yaml:"-"`
	NextCheckAt           *time.Time                 `json:"-" xml:"-" yaml:"-"`
	IncidentID            string                     `json:"-" xml:"-" yaml:"-"`
	AcknowledgmentID      string                     `json:"-" xml:"-" yaml:"-"`
	OpenCount             int                        `json:"-" xml:"-" yaml:"-"`
	AwaitingCount         int                        `json:"-" xml:"-" yaml:"-"`
	Snapshot              *UpdateEscalationSnapshot  `json:"-" xml:"-" yaml:"-"`
	OpenTargets           []string                   `json:"-" xml:"-" yaml:"-"`
	AwaitingTargets       []string                   `json:"-" xml:"-" yaml:"-"`
	Assignment            *UpdatePlanGroupAssignment `json:"-" xml:"-" yaml:"-"`
	original              []string
}

func (UpdateEscalation) String() string     { return "[protected Apple update escalation]" }
func (v UpdateEscalation) GoString() string { return v.String() }

type updateEscalationConfigurationWire struct {
	Version  int
	Original []string
}
type updateEscalationStateWire struct {
	Version        int
	Open, Awaiting []string
	Snapshot       *updateEscalationSnapshotWire
}

const updateEscalationColumns = `id,tenant_id,site_id,plan_id,assignment_id,configuration_revision,CASE WHEN octet_length(actor)<=255 THEN actor ELSE NULL END,actor_revision,enabled,created_at,configured_at,configuration_event_id,CASE WHEN octet_length(encrypted_configuration)<=8220 THEN encrypted_configuration ELSE NULL END,state_revision,CASE WHEN octet_length(phase)<=16 THEN phase ELSE NULL END,CASE WHEN octet_length(state_reason)<=32 THEN state_reason ELSE NULL END,updated_at,checked_at,next_check_at,incident_id,acknowledgment_id,open_count,awaiting_count,CASE WHEN octet_length(encrypted_state)<=131100 THEN encrypted_state ELSE NULL END`

func updateEscalationTime(at *time.Time) string {
	if at == nil {
		return "-"
	}
	return at.UTC().Format(time.RFC3339Nano)
}
func updateEscalationConfigurationPurpose(r *UpdateEscalation) string {
	return fmt.Sprintf("openuem/apple/update-escalation/config/v1/%s/%d/%d/%s/%s/%d/%x/%d/%t/%s/%s/%s", r.ID, r.Scope.TenantID, r.Scope.SiteID, r.PlanID, r.AssignmentID, r.ConfigurationRevision, sha256.Sum256([]byte(r.Actor)), r.ActorRevision, r.Enabled, r.CreatedAt.UTC().Format(time.RFC3339Nano), r.ConfiguredAt.UTC().Format(time.RFC3339Nano), r.ConfigurationEventID)
}
func updateEscalationStatePurpose(r *UpdateEscalation) string {
	return fmt.Sprintf("openuem/apple/update-escalation/state/v1/%s/%d/%d/%s/%s/%d/%s/%d/%s/%s/%s/%s/%s/%s/%s/%d/%d", r.ID, r.Scope.TenantID, r.Scope.SiteID, r.PlanID, r.AssignmentID, r.ConfigurationRevision, r.ConfigurationEventID, r.StateRevision, r.Phase, r.Reason, r.UpdatedAt.UTC().Format(time.RFC3339Nano), updateEscalationTime(r.CheckedAt), updateEscalationTime(r.NextCheckAt), r.IncidentID, r.AcknowledgmentID, r.OpenCount, r.AwaitingCount)
}

func validEscalationTargetIDs(ids []string) bool {
	if len(ids) > 100 || !slices.IsSorted(ids) {
		return false
	}
	for i, id := range ids {
		if !profileRevisionUUID(id) || (i > 0 && id == ids[i-1]) {
			return false
		}
	}
	return true
}

func (s *Store) openUpdateEscalationWire(encrypted []byte, purpose string, limit int, target any) error {
	plain, err := s.secrets.open(encrypted, purpose)
	defer clear(plain)
	if err != nil || len(plain) > limit {
		return ErrUpdateEscalationIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrUpdateEscalationIntegrity
	}
	return nil
}
func (s *Store) sealUpdateEscalationWire(value any, purpose string, limit int) ([]byte, error) {
	plain, err := json.Marshal(value)
	defer clear(plain)
	if err != nil || len(plain) > limit {
		return nil, ErrUpdateEscalationIntegrity
	}
	return s.secrets.seal(plain, purpose)
}

func validateUpdateEscalationState(r *UpdateEscalation) error {
	if !profileRevisionUUID(r.ID) || !profileRevisionUUID(r.PlanID) || !profileRevisionUUID(r.AssignmentID) || !profileRevisionUUID(r.ConfigurationEventID) || r.Scope.SiteID < 1 || r.Scope.TenantID < 1 || r.ConfigurationRevision < 1 || r.ConfigurationRevision > 2147483647 || r.StateRevision < int64(r.ConfigurationRevision) || r.ActorRevision < 0 || len(r.Actor) < 1 || len(r.Actor) > 255 || r.CreatedAt.IsZero() || r.ConfiguredAt.Before(r.CreatedAt) || r.UpdatedAt.Before(r.ConfiguredAt) || !validEscalationTargetIDs(r.original) || len(r.original) < 1 {
		return ErrUpdateEscalationIntegrity
	}
	switch r.Phase {
	case "watching":
		if !r.Enabled || r.Reason != "" || r.NextCheckAt == nil || r.NextCheckAt.Before(r.UpdatedAt) {
			return ErrUpdateEscalationIntegrity
		}
	case "paused":
		if r.Enabled || r.Reason != "" || r.NextCheckAt != nil {
			return ErrUpdateEscalationIntegrity
		}
	case "blocked":
		if !r.Enabled || r.NextCheckAt != nil || (r.Reason != "authority_changed" && r.Reason != "source_unavailable") {
			return ErrUpdateEscalationIntegrity
		}
	default:
		return ErrUpdateEscalationIntegrity
	}
	if !validEscalationTargetIDs(r.OpenTargets) || !validEscalationTargetIDs(r.AwaitingTargets) || len(r.OpenTargets) != r.OpenCount || len(r.AwaitingTargets) != r.AwaitingCount {
		return ErrUpdateEscalationIntegrity
	}
	for _, id := range r.OpenTargets {
		if _, found := slices.BinarySearch(r.original, id); !found {
			return ErrUpdateEscalationIntegrity
		}
	}
	if r.OpenCount == 0 {
		if r.IncidentID != "" || r.AcknowledgmentID != "" {
			return ErrUpdateEscalationIntegrity
		}
	} else if !profileRevisionUUID(r.IncidentID) {
		return ErrUpdateEscalationIntegrity
	}
	if r.AcknowledgmentID != "" && !profileRevisionUUID(r.AcknowledgmentID) {
		return ErrUpdateEscalationIntegrity
	}
	if r.Snapshot == nil {
		if r.CheckedAt != nil || r.OpenCount != 0 || r.AwaitingCount != 0 {
			return ErrUpdateEscalationIntegrity
		}
		return nil
	}
	if r.CheckedAt == nil || !r.CheckedAt.Equal(r.Snapshot.AssessedAt) || r.CheckedAt.Before(r.CreatedAt) || r.CheckedAt.After(r.UpdatedAt) {
		return ErrUpdateEscalationIntegrity
	}
	decisions := make([]UpdateEscalationDecision, 0, len(r.Snapshot.Devices))
	for _, d := range r.Snapshot.Devices {
		decisions = append(decisions, d.Decision)
	}
	open, awaiting, _, err := mergeUpdateEscalationTargets(r.OpenTargets, decisions)
	if err != nil || !slices.Equal(open, r.OpenTargets) || !slices.Equal(awaiting, r.AwaitingTargets) {
		return ErrUpdateEscalationIntegrity
	}
	return nil
}

func (s *Store) scanUpdateEscalation(row scanner) (*UpdateEscalation, error) {
	r := &UpdateEscalation{}
	var config, state []byte
	var incident, ack sql.NullString
	if err := row.Scan(&r.ID, &r.Scope.TenantID, &r.Scope.SiteID, &r.PlanID, &r.AssignmentID, &r.ConfigurationRevision, &r.Actor, &r.ActorRevision, &r.Enabled, &r.CreatedAt, &r.ConfiguredAt, &r.ConfigurationEventID, &config, &r.StateRevision, &r.Phase, &r.Reason, &r.UpdatedAt, &r.CheckedAt, &r.NextCheckAt, &incident, &ack, &r.OpenCount, &r.AwaitingCount, &state); err != nil {
		return nil, notFound(err)
	}
	r.IncidentID, r.AcknowledgmentID = incident.String, ack.String
	var configuration updateEscalationConfigurationWire
	if err := s.openUpdateEscalationWire(config, updateEscalationConfigurationPurpose(r), 8192, &configuration); err != nil {
		return nil, err
	}
	if configuration.Version != 1 {
		return nil, ErrUpdateEscalationIntegrity
	}
	r.original = configuration.Original
	var saved updateEscalationStateWire
	if err := s.openUpdateEscalationWire(state, updateEscalationStatePurpose(r), 131072, &saved); err != nil {
		return nil, err
	}
	if saved.Version != 1 {
		return nil, ErrUpdateEscalationIntegrity
	}
	r.OpenTargets, r.AwaitingTargets = saved.Open, saved.Awaiting
	var err error
	r.Snapshot, err = decodeEscalationSnapshot(saved.Snapshot, r.original)
	if err != nil {
		return nil, err
	}
	if err = validateUpdateEscalationState(r); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) sealUpdateEscalation(r *UpdateEscalation) (configuration, state []byte, err error) {
	if err = validateUpdateEscalationState(r); err != nil {
		return nil, nil, err
	}
	wire := escalationSnapshotWire(r.Snapshot)
	if _, err = decodeEscalationSnapshot(wire, r.original); err != nil {
		return nil, nil, err
	}
	configuration, err = s.sealUpdateEscalationWire(updateEscalationConfigurationWire{Version: 1, Original: r.original}, updateEscalationConfigurationPurpose(r), 8192)
	if err != nil {
		return nil, nil, err
	}
	state, err = s.sealUpdateEscalationWire(updateEscalationStateWire{Version: 1, Open: r.OpenTargets, Awaiting: r.AwaitingTargets, Snapshot: wire}, updateEscalationStatePurpose(r), 131072)
	return configuration, state, err
}
