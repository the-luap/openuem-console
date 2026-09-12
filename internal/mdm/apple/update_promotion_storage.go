package apple

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/open-uem/openuem-console/internal/inventory"
)

type UpdatePromotion struct {
	ID                  string                     `json:"-" xml:"-" yaml:"-"`
	Scope               Scope                      `json:"-" xml:"-" yaml:"-"`
	RequestKey          string                     `json:"-" xml:"-" yaml:"-"`
	PilotPlanID         string                     `json:"-" xml:"-" yaml:"-"`
	PilotAssignmentID   string                     `json:"-" xml:"-" yaml:"-"`
	DestinationPlanID   string                     `json:"-" xml:"-" yaml:"-"`
	AssignmentID        string                     `json:"-" xml:"-" yaml:"-"`
	Actor               string                     `json:"-" xml:"-" yaml:"-"`
	ActorRevision       int64                      `json:"-" xml:"-" yaml:"-"`
	CreatedAt           time.Time                  `json:"-" xml:"-" yaml:"-"`
	DestinationRevision int                        `json:"-" xml:"-" yaml:"-"`
	GroupID             string                     `json:"-" xml:"-" yaml:"-"`
	GroupRevision       int                        `json:"-" xml:"-" yaml:"-"`
	Targets             []UpdatePlanGroupSelection `json:"-" xml:"-" yaml:"-"`
	Evidence            *UpdatePilotEvidence       `json:"-" xml:"-" yaml:"-"`
	Pilot               *UpdatePlanGroupAssignment `json:"-" xml:"-" yaml:"-"`
	Assignment          *UpdatePlanGroupAssignment `json:"-" xml:"-" yaml:"-"`
	activationKey       string
	sources             inventory.DeviceSources
}

func (UpdatePromotion) String() string     { return "[protected Apple update promotion]" }
func (r UpdatePromotion) GoString() string { return r.String() }

type updatePromotionWire struct {
	Version             int
	DestinationRevision int
	GroupID             string
	GroupRevision       int
	Targets             []struct{ DeviceID, PolicyToken string }
	Evidence            *updatePilotEvidenceWire
	ActivationKey       string
	Sources             inventory.DeviceSources
}

const updatePromotionColumns = `id,tenant_id,site_id,request_key,pilot_plan_id,pilot_assignment_id,destination_plan_id,assignment_id,CASE WHEN octet_length(actor)<=255 THEN actor ELSE NULL END,actor_revision,created_at,CASE WHEN octet_length(encrypted_intent)<=131100 THEN encrypted_intent ELSE NULL END`

func updatePromotionPurpose(r *UpdatePromotion) string {
	return fmt.Sprintf("openuem/apple/update-promotion/v1/%s/%d/%d/%s/%s/%s/%s/%s/%x/%d/%s", r.ID, r.Scope.TenantID, r.Scope.SiteID, r.RequestKey, r.PilotPlanID, r.PilotAssignmentID, r.DestinationPlanID, r.AssignmentID, sha256.Sum256([]byte(r.Actor)), r.ActorRevision, r.CreatedAt.UTC().Format(time.RFC3339Nano))
}
func validUpdatePromotionMetadata(r *UpdatePromotion) bool {
	if r == nil || !profileRevisionUUID(r.ID) || !profileRevisionUUID(r.RequestKey) || !profileRevisionUUID(r.PilotPlanID) || !profileRevisionUUID(r.PilotAssignmentID) || !profileRevisionUUID(r.DestinationPlanID) || !profileRevisionUUID(r.AssignmentID) || r.AssignmentID == r.PilotAssignmentID || r.Scope.TenantID < 1 || r.Scope.SiteID < 1 || len(r.Actor) < 1 || len(r.Actor) > 255 || r.ActorRevision < 0 || r.CreatedAt.IsZero() || r.DestinationRevision < 1 || r.DestinationRevision > 2147483647 || !profileRevisionUUID(r.GroupID) || r.GroupRevision < 1 || r.GroupRevision > 2147483647 || !profileRevisionUUID(r.activationKey) || !r.sources.Apple || r.Evidence == nil || r.Evidence.AssessedAt.IsZero() || r.Evidence.AssessedAt.After(r.CreatedAt) || len(r.Evidence.Devices) < 1 || len(r.Evidence.Devices) > 100 {
		return false
	}
	canonical, err := canonicalUpdateGroupSelection(r.Targets)
	return err == nil && slices.Equal(canonical, r.Targets)
}
func promotionWire(r *UpdatePromotion) updatePromotionWire {
	w := updatePromotionWire{Version: 1, DestinationRevision: r.DestinationRevision, GroupID: r.GroupID, GroupRevision: r.GroupRevision, Evidence: pilotEvidenceWire(r.Evidence), ActivationKey: r.activationKey, Sources: r.sources}
	for _, target := range r.Targets {
		w.Targets = append(w.Targets, struct{ DeviceID, PolicyToken string }{target.DeviceID, target.PolicyToken})
	}
	return w
}
func (s *Store) sealUpdatePromotion(r *UpdatePromotion) ([]byte, error) {
	if !validUpdatePromotionMetadata(r) {
		return nil, ErrUpdatePromotionIntegrity
	}
	plain, err := json.Marshal(promotionWire(r))
	defer clear(plain)
	if err != nil || len(plain) > 131072 {
		return nil, ErrUpdatePromotionIntegrity
	}
	return s.secrets.seal(plain, updatePromotionPurpose(r))
}
func (s *Store) scanUpdatePromotion(row scanner) (*UpdatePromotion, error) {
	r := &UpdatePromotion{}
	var encrypted []byte
	if err := row.Scan(&r.ID, &r.Scope.TenantID, &r.Scope.SiteID, &r.RequestKey, &r.PilotPlanID, &r.PilotAssignmentID, &r.DestinationPlanID, &r.AssignmentID, &r.Actor, &r.ActorRevision, &r.CreatedAt, &encrypted); err != nil {
		return nil, notFound(err)
	}
	plain, err := s.secrets.open(encrypted, updatePromotionPurpose(r))
	defer clear(plain)
	if err != nil || len(plain) > 131072 {
		return nil, ErrUpdatePromotionIntegrity
	}
	var w updatePromotionWire
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&w) != nil || decoder.Decode(new(any)) != io.EOF || w.Version != 1 {
		return nil, ErrUpdatePromotionIntegrity
	}
	r.DestinationRevision, r.GroupID, r.GroupRevision, r.Evidence, r.activationKey, r.sources = w.DestinationRevision, w.GroupID, w.GroupRevision, decodePilotEvidence(w.Evidence), w.ActivationKey, w.Sources
	for _, target := range w.Targets {
		r.Targets = append(r.Targets, UpdatePlanGroupSelection{DeviceID: target.DeviceID, PolicyToken: target.PolicyToken})
	}
	if !validUpdatePromotionMetadata(r) {
		return nil, ErrUpdatePromotionIntegrity
	}
	return r, nil
}
func (s *Store) validateUpdatePromotionSources(ctx context.Context, tx *sql.Tx, r *UpdatePromotion) error {
	if !validUpdatePromotionMetadata(r) {
		return ErrUpdatePromotionIntegrity
	}
	pilot, err := s.scanUpdateGroupAssignment(tx.QueryRowContext(ctx, `SELECT `+updateGroupColumns+` FROM mdm_apple_update_group_assignments WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4`, r.PilotAssignmentID, r.Scope.TenantID, r.Scope.SiteID, r.PilotPlanID))
	if err != nil {
		return err
	}
	assignment, err := s.scanUpdateGroupAssignment(tx.QueryRowContext(ctx, `SELECT `+updateGroupColumns+` FROM mdm_apple_update_group_assignments WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4`, r.AssignmentID, r.Scope.TenantID, r.Scope.SiteID, r.DestinationPlanID))
	if err != nil {
		return err
	}
	if assignment.RequestKey != r.activationKey || assignment.Actor != r.Actor || assignment.ActorRevision != r.ActorRevision || assignment.Plan.Revision != r.DestinationRevision || assignment.Group.ID != r.GroupID || assignment.Group.Revision != r.GroupRevision || assignment.CreatedAt.Before(r.Evidence.AssessedAt) || assignment.CreatedAt.After(r.CreatedAt) || !UpdatePromotionTargetMatches(pilot.Plan.Definition, assignment.Plan.Definition) || len(assignment.Commands) != len(r.Targets) {
		return ErrUpdatePromotionIntegrity
	}
	originalIDs := make(map[string]bool, len(pilot.Commands))
	for _, command := range pilot.Commands {
		originalIDs[command.Selection.DeviceID] = true
	}
	newTargets := 0
	for i, command := range assignment.Commands {
		if command.Selection != r.Targets[i] {
			return ErrUpdatePromotionIntegrity
		}
		if !originalIDs[command.Selection.DeviceID] {
			newTargets++
		}
	}
	if newTargets == 0 {
		return ErrUpdatePromotionIntegrity
	}
	if err = validateUpdatePilotEvidence(r.Evidence, pilot, r.CreatedAt); err != nil {
		return err
	}
	r.Pilot, r.Assignment = pilot, assignment
	return nil
}
func (s *Store) insertUpdatePromotion(ctx context.Context, tx *sql.Tx, r *UpdatePromotion) error {
	if err := s.validateUpdatePromotionSources(ctx, tx, r); err != nil {
		return err
	}
	encrypted, err := s.sealUpdatePromotion(r)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_update_promotions(id,tenant_id,site_id,request_key,pilot_plan_id,pilot_assignment_id,destination_plan_id,assignment_id,actor,actor_revision,created_at,encrypted_intent) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, r.ID, r.Scope.TenantID, r.Scope.SiteID, r.RequestKey, r.PilotPlanID, r.PilotAssignmentID, r.DestinationPlanID, r.AssignmentID, r.Actor, r.ActorRevision, r.CreatedAt, encrypted)
	return err
}
