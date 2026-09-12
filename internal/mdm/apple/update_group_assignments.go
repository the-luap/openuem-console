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
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type UpdatePlanGroupCommand struct {
	Selection UpdatePlanGroupSelection `json:"-" xml:"-" yaml:"-"`
	CommandID string                   `json:"-" xml:"-" yaml:"-"`
}
type UpdatePlanGroupAssignment struct {
	GroupScope    Scope                    `json:"-" xml:"-" yaml:"-"`
	ID            string                   `json:"-" xml:"-" yaml:"-"`
	Scope         Scope                    `json:"-" xml:"-" yaml:"-"`
	RequestKey    string                   `json:"-" xml:"-" yaml:"-"`
	Plan          UpdatePlan               `json:"-" xml:"-" yaml:"-"`
	Actor         string                   `json:"-" xml:"-" yaml:"-"`
	ActorRevision int64                    `json:"-" xml:"-" yaml:"-"`
	Group         ProfileGroupSource       `json:"-" xml:"-" yaml:"-"`
	CreatedAt     time.Time                `json:"-" xml:"-" yaml:"-"`
	Commands      []UpdatePlanGroupCommand `json:"-" xml:"-" yaml:"-"`
}

func (UpdatePlanGroupCommand) String() string        { return "[protected Apple update group command]" }
func (v UpdatePlanGroupCommand) GoString() string    { return v.String() }
func (UpdatePlanGroupAssignment) String() string     { return "[protected Apple update group assignment]" }
func (v UpdatePlanGroupAssignment) GoString() string { return v.String() }

type updateGroupIntent struct {
	GroupScope    *Scope `json:",omitempty"`
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
	Targets []struct{ DeviceID, PolicyToken, CommandID string }
}

var updateGroupPolicyToken = regexp.MustCompile(`^[0-9a-f]{64}$`)

const updateGroupColumns = `id,tenant_id,site_id,request_key,plan_id,plan_revision,actor,actor_revision,created_at,CASE WHEN octet_length(encrypted_intent)<=32796 THEN encrypted_intent ELSE NULL END`

func updateGroupPurpose(r *UpdatePlanGroupAssignment) string {
	return fmt.Sprintf("openuem/apple/update-group/v1/%s/%d/%d/%s/%s/%d/%x/%d/%s", r.ID, r.Scope.TenantID, r.Scope.SiteID, r.RequestKey, r.Plan.ID, r.Plan.Revision, sha256.Sum256([]byte(r.Actor)), r.ActorRevision, r.CreatedAt.UTC().Format(time.RFC3339Nano))
}
func (s *Store) scanUpdateGroupAssignment(row scanner) (*UpdatePlanGroupAssignment, error) {
	r := &UpdatePlanGroupAssignment{}
	var encrypted []byte
	if err := row.Scan(&r.ID, &r.Scope.TenantID, &r.Scope.SiteID, &r.RequestKey, &r.Plan.ID, &r.Plan.Revision, &r.Actor, &r.ActorRevision, &r.CreatedAt, &encrypted); err != nil {
		return nil, notFound(err)
	}
	plain, err := s.secrets.open(encrypted, updateGroupPurpose(r))
	defer clear(plain)
	if err != nil || len(plain) > 32768 {
		return nil, ErrUpdatePlanGroupIntegrity
	}
	var wire updateGroupIntent
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(new(any)) != io.EOF || (wire.Version != 1 && wire.Version != 2) || wire.Plan.Version != 1 || wire.PlanCreatedAt.IsZero() || len(wire.PlanActor) < 1 || len(wire.PlanActor) > 255 || !profileRevisionUUID(wire.Group.ID) || wire.Group.Revision < 1 || wire.Group.Revision > 2147483647 || !(inventory.DeviceGroupDefinition{Name: wire.Group.Name, Rule: wire.Group.Rule}).Valid() || len(wire.Targets) < 1 || len(wire.Targets) > 100 {
		return nil, ErrUpdatePlanGroupIntegrity
	}
	if wire.Version == 1 {
		if wire.GroupScope != nil {
			return nil, ErrUpdatePlanGroupIntegrity
		}
		r.GroupScope = r.Scope
	} else {
		if wire.GroupScope == nil || !validAppleGroupSourceScope(*wire.GroupScope, r.Scope) {
			return nil, ErrUpdatePlanGroupIntegrity
		}
		r.GroupScope = *wire.GroupScope
	}
	r.Plan.Scope = r.Scope
	r.Plan.Actor = wire.PlanActor
	r.Plan.CreatedAt = wire.PlanCreatedAt
	d := wire.Plan
	r.Plan.Definition = UpdatePlanDefinition{Name: d.Name, Description: d.Description, Platform: d.Platform, TargetVersion: d.TargetVersion, TargetBuild: d.TargetBuild, Deadline: d.Deadline, DetailsURL: d.DetailsURL, Archived: d.Archived}
	if !r.Plan.Definition.Valid() || r.Plan.Definition.Archived {
		return nil, ErrUpdatePlanGroupIntegrity
	}
	r.Group = ProfileGroupSource{ID: wire.Group.ID, Revision: wire.Group.Revision, Name: wire.Group.Name, Rule: wire.Group.Rule}
	previous := ""
	commands := map[string]bool{}
	for _, target := range wire.Targets {
		if !profileRevisionUUID(target.DeviceID) || target.DeviceID <= previous || !updateGroupPolicyToken.MatchString(target.PolicyToken) || !profileRevisionUUID(target.CommandID) || commands[target.CommandID] {
			return nil, ErrUpdatePlanGroupIntegrity
		}
		previous = target.DeviceID
		commands[target.CommandID] = true
		r.Commands = append(r.Commands, UpdatePlanGroupCommand{Selection: UpdatePlanGroupSelection{DeviceID: target.DeviceID, PolicyToken: target.PolicyToken}, CommandID: target.CommandID})
	}
	return r, nil
}
func (s *Store) sealUpdateGroupAssignment(r *UpdatePlanGroupAssignment) ([]byte, error) {
	d := r.Plan.Definition
	if !validAppleGroupSourceScope(r.GroupScope, r.Scope) {
		return nil, ErrUpdatePlanGroupIntegrity
	}
	wire := updateGroupIntent{Version: 2, GroupScope: &r.GroupScope, PlanActor: r.Plan.Actor, PlanCreatedAt: r.Plan.CreatedAt, Plan: updatePlanWire{Version: 1, Name: d.Name, Description: d.Description, Platform: d.Platform, TargetVersion: d.TargetVersion, TargetBuild: d.TargetBuild, Deadline: d.Deadline, DetailsURL: d.DetailsURL, Archived: d.Archived}}
	wire.Group.ID, wire.Group.Revision, wire.Group.Name, wire.Group.Rule = r.Group.ID, r.Group.Revision, r.Group.Name, r.Group.Rule
	for _, target := range r.Commands {
		wire.Targets = append(wire.Targets, struct{ DeviceID, PolicyToken, CommandID string }{target.Selection.DeviceID, target.Selection.PolicyToken, target.CommandID})
	}
	plain, err := json.Marshal(wire)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	if len(plain) > 32768 {
		return nil, ErrUpdatePlanGroup
	}
	return s.secrets.seal(plain, updateGroupPurpose(r))
}

func canonicalUpdateGroupSelection(selection []UpdatePlanGroupSelection) ([]UpdatePlanGroupSelection, error) {
	if len(selection) < 1 || len(selection) > 100 {
		return nil, ErrUpdatePlanGroup
	}
	targets := slices.Clone(selection)
	slices.SortFunc(targets, func(a, b UpdatePlanGroupSelection) int {
		if a.DeviceID < b.DeviceID {
			return -1
		}
		if a.DeviceID > b.DeviceID {
			return 1
		}
		return 0
	})
	for i, target := range targets {
		if !profileRevisionUUID(target.DeviceID) || !updateGroupPolicyToken.MatchString(target.PolicyToken) || (i > 0 && targets[i-1].DeviceID == target.DeviceID) {
			return nil, ErrUpdatePlanGroup
		}
	}
	return targets, nil
}

// AssignUpdatePlanFromGroup accepts only the complete reviewed eligible native
// selection and its unchanged configured policies. Exact retry returns original
// admission evidence before consulting mutable plan, group or device state.
func (s *Store) AssignUpdatePlanFromGroup(ctx context.Context, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, planID string, planRevision int, groupID string, groupRevision int, requestKey string, selection []UpdatePlanGroupSelection) (*UpdatePlanGroupAssignment, error) {
	return s.assignUpdatePlanFromGroupSource(ctx, actor, permissions, scope, scope, sources, planID, planRevision, groupID, groupRevision, requestKey, selection)
}

func (s *Store) assignUpdatePlanFromGroupSource(ctx context.Context, actor string, permissions *access.Store, scope, groupScope Scope, sources inventory.DeviceSources, planID string, planRevision int, groupID string, groupRevision int, requestKey string, selection []UpdatePlanGroupSelection) (*UpdatePlanGroupAssignment, error) {
	if !sources.Apple || !profileRevisionUUID(planID) || planRevision < 1 || planRevision > 2147483647 || !profileRevisionUUID(groupID) || groupRevision < 1 || groupRevision > 2147483647 || !profileRevisionUUID(requestKey) || len(selection) < 1 || len(selection) > 100 {
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
	r, err := s.assignUpdatePlanGroupSourceTransaction(ctx, tx, actor, permissions, scope, groupScope, sources, planID, planRevision, groupID, groupRevision, requestKey, targets)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

// assignUpdatePlanGroupTransaction lets scheduled activation retain its state
// transition and device admission in one transaction. Targets and source IDs
// must already be canonical and validated by the caller.
func (s *Store) assignUpdatePlanGroupTransaction(ctx context.Context, tx *sql.Tx, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, planID string, planRevision int, groupID string, groupRevision int, requestKey string, targets []UpdatePlanGroupSelection) (*UpdatePlanGroupAssignment, error) {
	return s.assignUpdatePlanGroupSourceTransaction(ctx, tx, actor, permissions, scope, scope, sources, planID, planRevision, groupID, groupRevision, requestKey, targets)
}

func (s *Store) assignUpdatePlanGroupSourceTransaction(ctx context.Context, tx *sql.Tx, actor string, permissions *access.Store, scope, groupScope Scope, sources inventory.DeviceSources, planID string, planRevision int, groupID string, groupRevision int, requestKey string, targets []UpdatePlanGroupSelection) (*UpdatePlanGroupAssignment, error) {
	var err error
	if err = updatePlanAuthority(ctx, tx, permissions, actor, scope, access.ManageUpdates); err != nil {
		return nil, err
	}
	if !validAppleGroupSourceScope(groupScope, scope) {
		return nil, ErrUpdatePlanGroup
	}
	if groupScope != scope {
		if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ReadDevices, access.Scope{TenantID: groupScope.TenantID, SiteID: groupScope.SiteID}); err != nil {
			return nil, err
		}
	}
	var actorRevision int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT revision FROM uem_access_revisions WHERE user_id=$1),0)`, actor).Scan(&actorRevision); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629906,hashtext($1))`, fmt.Sprintf("%d/%d/%s", scope.TenantID, scope.SiteID, requestKey)); err != nil {
		return nil, err
	}
	previous, err := s.scanUpdateGroupAssignment(tx.QueryRowContext(ctx, `SELECT `+updateGroupColumns+` FROM mdm_apple_update_group_assignments WHERE tenant_id=$1 AND site_id=$2 AND request_key=$3`, scope.TenantID, scope.SiteID, requestKey))
	if err == nil {
		original := make([]UpdatePlanGroupSelection, len(previous.Commands))
		for i, command := range previous.Commands {
			original[i] = command.Selection
		}
		if previous.GroupScope != groupScope || previous.Actor != actor || previous.ActorRevision != actorRevision || previous.Plan.ID != planID || previous.Plan.Revision != planRevision || previous.Group.ID != groupID || previous.Group.Revision != groupRevision || !slices.Equal(original, targets) {
			return nil, ErrConflict
		}
		if err = auditUpdatePlan(ctx, tx, scope, actor, "group.replayed", previous.ID, planRevision); err != nil {
			return nil, err
		}
		return previous, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	preview, err := s.inspectUpdatePlanGroupSourceWithPilot(ctx, tx, actor, permissions, scope, groupScope, sources, planID, planRevision, groupID, groupRevision, true, nil)
	if err != nil {
		return nil, err
	}
	current := make([]UpdatePlanGroupSelection, len(preview.Targets))
	for i, target := range preview.Targets {
		current[i] = target.Selection
	}
	if !slices.Equal(current, targets) {
		return nil, ErrConflict
	}
	return s.writeUpdatePlanGroupAssignment(ctx, tx, actor, actorRevision, scope, requestKey, preview)
}

// The caller owns current action authority, source locks and exclusive locks on
// every reviewed native target, and has compared the complete canonical selection.
// A promotion can keep its pilot proof and this admission in one transaction
// without re-reading an unrelated later membership snapshot.
func (s *Store) writeUpdatePlanGroupAssignment(ctx context.Context, tx *sql.Tx, actor string, actorRevision int64, scope Scope, requestKey string, preview *UpdatePlanGroupPreview) (*UpdatePlanGroupAssignment, error) {
	var err error
	r := &UpdatePlanGroupAssignment{GroupScope: Scope{TenantID: preview.Group.Scope.TenantID, SiteID: preview.Group.Scope.SiteID}, ID: uuid.NewString(), Scope: scope, RequestKey: requestKey, Plan: preview.Plan, Actor: actor, ActorRevision: actorRevision, Group: ProfileGroupSource{ID: preview.Group.ID, Revision: preview.Group.Revision, Name: preview.Group.Name, Rule: preview.Group.Rule}}
	policy := preview.Plan.Definition.Policy()
	for _, target := range preview.Targets {
		d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE tenant_id=$1 AND site_id=$2 AND id=$3`, scope.TenantID, scope.SiteID, target.Selection.DeviceID))
		if err != nil {
			return nil, err
		}
		if err = s.setDeviceUpdatePolicy(ctx, tx, d, &policy); err != nil {
			return nil, err
		}
		command := UpdatePlanGroupCommand{Selection: target.Selection}
		if err = tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_commands WHERE tenant_id=$1 AND device_id=$2 AND request_type='DeclarativeManagement' AND status='queued'`, scope.TenantID, d.ID).Scan(&command.CommandID); err != nil {
			return nil, err
		}
		r.Commands = append(r.Commands, command)
		if err = audit(ctx, tx, scope.TenantID, actor, "apple.update.policy", d.ID); err != nil {
			return nil, err
		}
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&r.CreatedAt); err != nil {
		return nil, err
	}
	encrypted, err := s.sealUpdateGroupAssignment(r)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_update_group_assignments(id,tenant_id,site_id,request_key,plan_id,plan_revision,actor,actor_revision,created_at,encrypted_intent) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, r.ID, scope.TenantID, scope.SiteID, requestKey, r.Plan.ID, r.Plan.Revision, actor, actorRevision, r.CreatedAt, encrypted); err != nil {
		return nil, err
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "group.created", r.ID, preview.Plan.Revision); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) UpdatePlanGroupAssignmentDetails(ctx context.Context, actor string, permissions *access.Store, scope Scope, planID, id string) (*UpdatePlanGroupAssignment, error) {
	if !profileRevisionUUID(planID) || !profileRevisionUUID(id) {
		return nil, ErrUpdatePlanGroup
	}
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
	r, err := s.scanUpdateGroupAssignment(tx.QueryRowContext(ctx, `SELECT `+updateGroupColumns+` FROM mdm_apple_update_group_assignments WHERE tenant_id=$1 AND site_id=$2 AND plan_id=$3 AND id=$4`, scope.TenantID, scope.SiteID, planID, id))
	if err != nil {
		return nil, err
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "group.read", id, r.Plan.Revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}
func (s *Store) UpdatePlanGroupAssignments(ctx context.Context, actor string, permissions *access.Store, scope Scope, planID, before string) ([]UpdatePlanGroupAssignment, string, error) {
	if !profileRevisionUUID(planID) || (before != "" && !profileRevisionUUID(before)) {
		return nil, "", ErrUpdatePlanGroup
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	if err = updatePlanAuthority(ctx, tx, permissions, actor, scope, access.ManageUpdates); err != nil {
		return nil, "", err
	}
	var stamp, cursor any
	if before != "" {
		var at time.Time
		if err = tx.QueryRowContext(ctx, `SELECT created_at FROM mdm_apple_update_group_assignments WHERE tenant_id=$1 AND site_id=$2 AND plan_id=$3 AND id=$4`, scope.TenantID, scope.SiteID, planID, before).Scan(&at); err != nil {
			return nil, "", notFound(err)
		}
		stamp, cursor = at, before
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+updateGroupColumns+` FROM mdm_apple_update_group_assignments WHERE tenant_id=$1 AND site_id=$2 AND plan_id=$3 AND ($4::timestamptz IS NULL OR (created_at,id)<($4,$5::uuid)) ORDER BY created_at DESC,id DESC LIMIT 26`, scope.TenantID, scope.SiteID, planID, stamp, cursor)
	if err != nil {
		return nil, "", err
	}
	items := []UpdatePlanGroupAssignment{}
	for rows.Next() {
		r, err := s.scanUpdateGroupAssignment(rows)
		if err != nil {
			rows.Close()
			return nil, "", err
		}
		items = append(items, *r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) > 25 {
		next = items[24].ID
		items = items[:25]
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "group.list", planID, 0); err != nil {
		return nil, "", err
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	return items, next, nil
}
