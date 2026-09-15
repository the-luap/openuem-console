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
	"github.com/open-uem/openuem-console/internal/security/access"
)

type UpdateGroupRemoval struct {
	ID            string                    `json:"-" xml:"-" yaml:"-"`
	Scope         Scope                     `json:"-" xml:"-" yaml:"-"`
	RequestKey    string                    `json:"-" xml:"-" yaml:"-"`
	Assignment    UpdatePlanGroupAssignment `json:"-" xml:"-" yaml:"-"`
	Actor         string                    `json:"-" xml:"-" yaml:"-"`
	ActorRevision int64                     `json:"-" xml:"-" yaml:"-"`
	CreatedAt     time.Time                 `json:"-" xml:"-" yaml:"-"`
	Commands      []UpdatePlanGroupCommand  `json:"-" xml:"-" yaml:"-"`
}

func (UpdateGroupRemoval) String() string     { return "[protected Apple update group removal]" }
func (v UpdateGroupRemoval) GoString() string { return v.String() }

type updateGroupRemovalWire struct {
	Version int
	Targets []struct{ DeviceID, PolicyToken, CommandID string }
}

const updateGroupRemovalColumns = `id,tenant_id,site_id,request_key,plan_id,assignment_id,actor,actor_revision,created_at,CASE WHEN octet_length(encrypted_intent)<=32796 THEN encrypted_intent ELSE NULL END`

func updateGroupRemovalPurpose(r *UpdateGroupRemoval) string {
	return fmt.Sprintf("openuem/apple/update-group/removal/v1/%s/%d/%d/%s/%s/%s/%x/%d/%s", r.ID, r.Scope.TenantID, r.Scope.SiteID, r.RequestKey, r.Assignment.Plan.ID, r.Assignment.ID, sha256.Sum256([]byte(r.Actor)), r.ActorRevision, r.CreatedAt.UTC().Format(time.RFC3339Nano))
}

func (s *Store) scanUpdateGroupRemoval(row scanner) (*UpdateGroupRemoval, error) {
	r := &UpdateGroupRemoval{}
	var encrypted []byte
	if err := row.Scan(&r.ID, &r.Scope.TenantID, &r.Scope.SiteID, &r.RequestKey, &r.Assignment.Plan.ID, &r.Assignment.ID, &r.Actor, &r.ActorRevision, &r.CreatedAt, &encrypted); err != nil {
		return nil, notFound(err)
	}
	plain, err := s.secrets.open(encrypted, updateGroupRemovalPurpose(r))
	defer clear(plain)
	if err != nil || len(plain) > 32768 {
		return nil, ErrUpdatePlanGroupIntegrity
	}
	var wire updateGroupRemovalWire
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(new(any)) != io.EOF || wire.Version != 1 || len(wire.Targets) < 1 || len(wire.Targets) > 100 {
		return nil, ErrUpdatePlanGroupIntegrity
	}
	previous := ""
	commands := map[string]bool{}
	for _, target := range wire.Targets {
		if !profileRevisionUUID(target.DeviceID) || target.DeviceID <= previous || !updateGroupPolicyToken.MatchString(target.PolicyToken) || (target.CommandID != "" && (!profileRevisionUUID(target.CommandID) || commands[target.CommandID])) {
			return nil, ErrUpdatePlanGroupIntegrity
		}
		previous = target.DeviceID
		commands[target.CommandID] = true
		r.Commands = append(r.Commands, UpdatePlanGroupCommand{Selection: UpdatePlanGroupSelection{DeviceID: target.DeviceID, PolicyToken: target.PolicyToken}, CommandID: target.CommandID})
	}
	return r, nil
}

func (s *Store) sealUpdateGroupRemoval(r *UpdateGroupRemoval) ([]byte, error) {
	wire := updateGroupRemovalWire{Version: 1}
	for _, command := range r.Commands {
		wire.Targets = append(wire.Targets, struct{ DeviceID, PolicyToken, CommandID string }{command.Selection.DeviceID, command.Selection.PolicyToken, command.CommandID})
	}
	plain, err := json.Marshal(wire)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	if len(plain) > 32768 {
		return nil, ErrUpdatePlanGroup
	}
	return s.secrets.seal(plain, updateGroupRemovalPurpose(r))
}

func (s *Store) validateUpdateGroupRemoval(ctx context.Context, tx *sql.Tx, r *UpdateGroupRemoval) error {
	original, err := s.scanUpdateGroupAssignment(tx.QueryRowContext(ctx, `SELECT `+updateGroupColumns+` FROM mdm_apple_update_group_assignments WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4`, r.Assignment.ID, r.Scope.TenantID, r.Scope.SiteID, r.Assignment.Plan.ID))
	if err != nil {
		return err
	}
	if r.CreatedAt.Before(original.CreatedAt) {
		return ErrUpdatePlanGroupIntegrity
	}
	ids := map[string]bool{}
	for _, command := range original.Commands {
		ids[command.Selection.DeviceID] = true
	}
	policy := original.Plan.Definition.Policy()
	for _, command := range r.Commands {
		if !ids[command.Selection.DeviceID] || command.Selection.PolicyToken != updateGroupRemovalToken(r.Scope, command.Selection.DeviceID, &policy, command.CommandID != "") {
			return ErrUpdatePlanGroupIntegrity
		}
	}
	r.Assignment = *original
	return nil
}

// RemoveUpdateGroupPolicies atomically removes the complete reviewed eligible
// selection. Exact retry returns its original receipt without rearming commands.
func (s *Store) RemoveUpdateGroupPolicies(ctx context.Context, actor string, permissions *access.Store, scope Scope, planID, assignmentID, requestKey string, selection []UpdatePlanGroupSelection) (*UpdateGroupRemoval, error) {
	if !profileRevisionUUID(planID) || !profileRevisionUUID(assignmentID) || !profileRevisionUUID(requestKey) {
		return nil, ErrUpdatePlanGroup
	}
	targets, err := canonicalUpdateGroupSelection(selection)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = updateGroupRemovalAuthority(ctx, tx, permissions, actor, scope); err != nil {
		return nil, err
	}
	var actorRevision int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT revision FROM uem_access_revisions WHERE user_id=$1),0)`, actor).Scan(&actorRevision); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629908,hashtext($1))`, fmt.Sprintf("%d/%d/%s", scope.TenantID, scope.SiteID, requestKey)); err != nil {
		return nil, err
	}
	previous, err := s.scanUpdateGroupRemoval(tx.QueryRowContext(ctx, `SELECT `+updateGroupRemovalColumns+` FROM mdm_apple_update_group_removals WHERE tenant_id=$1 AND site_id=$2 AND request_key=$3`, scope.TenantID, scope.SiteID, requestKey))
	if err == nil {
		original := make([]UpdatePlanGroupSelection, len(previous.Commands))
		for i, command := range previous.Commands {
			original[i] = command.Selection
		}
		if previous.Actor != actor || previous.ActorRevision != actorRevision || previous.Assignment.Plan.ID != planID || previous.Assignment.ID != assignmentID || !slices.Equal(original, targets) {
			return nil, ErrConflict
		}
		if err = s.validateUpdateGroupRemoval(ctx, tx, previous); err != nil {
			return nil, err
		}
		if err = auditUpdatePlan(ctx, tx, scope, actor, "group.removal.replayed", previous.ID, previous.Assignment.Plan.Revision); err != nil {
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
	p, err := s.inspectUpdateGroupRemoval(ctx, tx, scope, planID, assignmentID, true)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(updateGroupRemovalSelection(p), targets) {
		return nil, ErrConflict
	}
	r := &UpdateGroupRemoval{ID: uuid.NewString(), Scope: scope, RequestKey: requestKey, Assignment: p.Assignment, Actor: actor, ActorRevision: actorRevision}
	for _, target := range p.Devices {
		if target.Reason != "" {
			continue
		}
		if err = s.setDeviceUpdatePolicy(ctx, tx, target.device, nil); err != nil {
			return nil, err
		}
		command := UpdatePlanGroupCommand{Selection: target.Selection}
		if target.NotificationAvailable {
			if err = tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_commands WHERE tenant_id=$1 AND device_id=$2 AND request_type='DeclarativeManagement' AND status='queued'`, scope.TenantID, target.Selection.DeviceID).Scan(&command.CommandID); err != nil {
				return nil, err
			}
		}
		r.Commands = append(r.Commands, command)
		if err = audit(ctx, tx, scope.TenantID, actor, "apple.update.policy", target.Selection.DeviceID); err != nil {
			return nil, err
		}
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&r.CreatedAt); err != nil {
		return nil, err
	}
	if r.CreatedAt.Before(p.Assignment.CreatedAt) {
		return nil, ErrUpdatePlanGroupIntegrity
	}
	encrypted, err := s.sealUpdateGroupRemoval(r)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_update_group_removals(id,tenant_id,site_id,request_key,plan_id,assignment_id,actor,actor_revision,created_at,encrypted_intent) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, r.ID, scope.TenantID, scope.SiteID, requestKey, planID, assignmentID, actor, actorRevision, r.CreatedAt, encrypted); err != nil {
		return nil, err
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "group.removal.created", r.ID, p.Assignment.Plan.Revision); err != nil {
		return nil, err
	}
	var completedAt time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&completedAt); err != nil {
		return nil, err
	}
	for _, target := range p.Devices {
		if target.Reason == "" && !target.device.CertificateExpiresAt.After(completedAt) {
			return nil, ErrConflict
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}
