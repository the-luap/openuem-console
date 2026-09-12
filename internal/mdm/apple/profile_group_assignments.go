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

type ProfileGroupSource struct {
	ID       string                    `json:"-" xml:"-" yaml:"-"`
	Revision int                       `json:"-" xml:"-" yaml:"-"`
	Name     string                    `json:"-" xml:"-" yaml:"-"`
	Rule     inventory.DeviceGroupRule `json:"-" xml:"-" yaml:"-"`
}

type ProfileGroupCommand struct {
	DeviceID  string `json:"-" xml:"-" yaml:"-"`
	CommandID string `json:"-" xml:"-" yaml:"-"`
}

type ProfileGroupAssignment struct {
	GroupScope      Scope                 `json:"-" xml:"-" yaml:"-"`
	ID              string                `json:"-" xml:"-" yaml:"-"`
	Scope           Scope                 `json:"-" xml:"-" yaml:"-"`
	RequestKey      string                `json:"-" xml:"-" yaml:"-"`
	ProfileID       string                `json:"-" xml:"-" yaml:"-"`
	ProfileRevision int                   `json:"-" xml:"-" yaml:"-"`
	ProfileName     string                `json:"-" xml:"-" yaml:"-"`
	Actor           string                `json:"-" xml:"-" yaml:"-"`
	ActorRevision   int64                 `json:"-" xml:"-" yaml:"-"`
	Desired         string                `json:"-" xml:"-" yaml:"-"`
	CreatedAt       time.Time             `json:"-" xml:"-" yaml:"-"`
	Group           ProfileGroupSource    `json:"-" xml:"-" yaml:"-"`
	Commands        []ProfileGroupCommand `json:"-" xml:"-" yaml:"-"`
}

func (ProfileGroupSource) String() string         { return "[protected Apple group source]" }
func (v ProfileGroupSource) GoString() string     { return v.String() }
func (ProfileGroupCommand) String() string        { return "[protected Apple group command]" }
func (v ProfileGroupCommand) GoString() string    { return v.String() }
func (ProfileGroupAssignment) String() string     { return "[protected Apple group assignment]" }
func (v ProfileGroupAssignment) GoString() string { return v.String() }

type profileGroupIntent struct {
	GroupScope  *Scope `json:",omitempty"`
	Version     int
	ProfileName string
	Group       struct {
		ID       string
		Revision int
		Name     string
		Rule     inventory.DeviceGroupRule
	}
	Targets []struct{ DeviceID, CommandID string }
}

const profileGroupColumns = `id,tenant_id,site_id,request_key,profile_id,profile_revision,actor,actor_revision,desired,created_at,CASE WHEN octet_length(encrypted_intent)<=16412 THEN encrypted_intent ELSE NULL END`

func profileGroupPurpose(r *ProfileGroupAssignment) string {
	return fmt.Sprintf("openuem/apple/profile-group/v1/%s/%d/%d/%s/%s/%d/%x/%d/%s/%s", r.ID, r.Scope.TenantID, r.Scope.SiteID, r.RequestKey, r.ProfileID, r.ProfileRevision, sha256.Sum256([]byte(r.Actor)), r.ActorRevision, r.Desired, r.CreatedAt.UTC().Format(time.RFC3339Nano))
}

func (s *Store) readProfileGroupAssignment(row scanner) (*ProfileGroupAssignment, error) {
	r := &ProfileGroupAssignment{}
	var encrypted []byte
	if err := row.Scan(&r.ID, &r.Scope.TenantID, &r.Scope.SiteID, &r.RequestKey, &r.ProfileID, &r.ProfileRevision, &r.Actor, &r.ActorRevision, &r.Desired, &r.CreatedAt, &encrypted); err != nil {
		return nil, notFound(err)
	}
	plain, err := s.secrets.open(encrypted, profileGroupPurpose(r))
	if err != nil || len(plain) > 16384 {
		clear(plain)
		return nil, ErrProfileGroupIntegrity
	}
	defer clear(plain)
	var intent profileGroupIntent
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&intent) != nil || decoder.Decode(new(any)) != io.EOF || (intent.Version != 1 && intent.Version != 2) || !profileRevisionUUID(intent.Group.ID) || intent.Group.Revision < 1 || intent.Group.Revision > 2147483647 || !(inventory.DeviceGroupDefinition{Name: intent.Group.Name, Rule: intent.Group.Rule}).Valid() || len(intent.Targets) < 1 || len(intent.Targets) > 100 {
		return nil, ErrProfileGroupIntegrity
	}
	if intent.Version == 1 {
		if intent.GroupScope != nil {
			return nil, ErrProfileGroupIntegrity
		}
		r.GroupScope = r.Scope
	} else {
		if intent.GroupScope == nil || !validProfileGroupSourceScope(*intent.GroupScope, r.Scope) {
			return nil, ErrProfileGroupIntegrity
		}
		r.GroupScope = *intent.GroupScope
	}
	previous := ""
	commands := map[string]bool{}
	for _, target := range intent.Targets {
		if !profileRevisionUUID(target.DeviceID) || !profileRevisionUUID(target.CommandID) || previous >= target.DeviceID || commands[target.CommandID] {
			return nil, ErrProfileGroupIntegrity
		}
		previous, commands[target.CommandID] = target.DeviceID, true
		r.Commands = append(r.Commands, ProfileGroupCommand{DeviceID: target.DeviceID, CommandID: target.CommandID})
	}
	r.ProfileName = intent.ProfileName
	r.Group = ProfileGroupSource{ID: intent.Group.ID, Revision: intent.Group.Revision, Name: intent.Group.Name, Rule: intent.Group.Rule}
	return r, nil
}

func (s *Store) sealProfileGroupAssignment(r *ProfileGroupAssignment) ([]byte, error) {
	if !validProfileGroupSourceScope(r.GroupScope, r.Scope) {
		return nil, ErrProfileGroupIntegrity
	}
	intent := profileGroupIntent{Version: 2, ProfileName: r.ProfileName, GroupScope: &r.GroupScope}
	intent.Group.ID, intent.Group.Revision, intent.Group.Name, intent.Group.Rule = r.Group.ID, r.Group.Revision, r.Group.Name, r.Group.Rule
	for _, target := range r.Commands {
		intent.Targets = append(intent.Targets, struct{ DeviceID, CommandID string }{target.DeviceID, target.CommandID})
	}
	plain, err := json.Marshal(intent)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	if len(plain) > 16384 {
		return nil, ErrProfileGroup
	}
	return s.secrets.seal(plain, profileGroupPurpose(r))
}

func profileGroupAuthority(ctx context.Context, tx *sql.Tx, permissions *access.Store, actor string, scope Scope) (int64, error) {
	if permissions == nil || scope.TenantID <= 0 || scope.SiteID <= 0 {
		return 0, access.ErrDenied
	}
	if err := permissions.AuthorizeTransaction(ctx, tx, actor, access.AssignProfiles, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}); err != nil {
		return 0, err
	}
	var site int
	if err := tx.QueryRowContext(ctx, `SELECT s.id FROM sites s JOIN tenants t ON t.id=s.tenant_sites WHERE t.id=$1 AND s.id=$2 FOR SHARE OF s,t`, scope.TenantID, scope.SiteID).Scan(&site); err != nil {
		return 0, notFound(err)
	}
	var revision int64
	err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT revision FROM uem_access_revisions WHERE user_id=$1),0)`, actor).Scan(&revision)
	return revision, err
}

func auditProfileGroupAssignment(ctx context.Context, tx *sql.Tx, r *ProfileGroupAssignment, actor, action string) error {
	details, err := json.Marshal(map[string]any{"site_id": r.Scope.SiteID, "result": "success"})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,details) VALUES($1,$2,$3,$4,$5)`, r.Scope.TenantID, actor, "apple.profile.group."+action, r.ID, details)
	return err
}

// AssignProfileFromGroup commits only the exact reviewed eligible target set.
// An exact request retry reads its original receipt before resolving current
// group/catalog state, so it cannot silently repeat or rewrite old device work.
func (s *Store) AssignProfileFromGroup(ctx context.Context, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, profileID string, profileRevision int, groupID string, groupRevision int, requestKey string, deviceIDs []string, desired string) (*ProfileGroupAssignment, error) {
	return s.assignProfileFromGroupSource(ctx, actor, permissions, scope, scope, sources, profileID, profileRevision, groupID, groupRevision, requestKey, deviceIDs, desired)
}

func (s *Store) assignProfileFromGroupSource(ctx context.Context, actor string, permissions *access.Store, scope, groupScope Scope, sources inventory.DeviceSources, profileID string, profileRevision int, groupID string, groupRevision int, requestKey string, deviceIDs []string, desired string) (*ProfileGroupAssignment, error) {
	if !validProfileGroupSourceScope(groupScope, scope) {
		return nil, ErrProfileGroup
	}
	if !sources.Apple || !profileRevisionUUID(profileID) || profileRevision < 1 || profileRevision > 2147483647 || !profileRevisionUUID(groupID) || groupRevision < 1 || groupRevision > 2147483647 || !profileRevisionUUID(requestKey) || (desired != "installed" && desired != "removed") || len(deviceIDs) < 1 || len(deviceIDs) > 100 {
		return nil, ErrProfileGroup
	}
	targets := slices.Clone(deviceIDs)
	slices.Sort(targets)
	for i, id := range targets {
		if !profileRevisionUUID(id) || (i > 0 && targets[i-1] == id) {
			return nil, ErrProfileGroup
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	permissionRevision, err := profileGroupAuthority(ctx, tx, permissions, actor, scope)
	if err != nil {
		return nil, err
	}
	if groupScope != scope {
		if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ReadDevices, access.Scope{TenantID: groupScope.TenantID, SiteID: groupScope.SiteID}); err != nil {
			return nil, err
		}
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629904,hashtext($1))`, fmt.Sprintf("%d/%d/%s", scope.TenantID, scope.SiteID, requestKey)); err != nil {
		return nil, err
	}
	previous, err := s.readProfileGroupAssignment(tx.QueryRowContext(ctx, `SELECT `+profileGroupColumns+` FROM mdm_apple_profile_group_assignments WHERE tenant_id=$1 AND site_id=$2 AND request_key=$3`, scope.TenantID, scope.SiteID, requestKey))
	if err == nil {
		original := make([]string, len(previous.Commands))
		for i, command := range previous.Commands {
			original[i] = command.DeviceID
		}
		if previous.GroupScope != groupScope || previous.Actor != actor || previous.ActorRevision != permissionRevision || previous.ProfileID != profileID || previous.ProfileRevision != profileRevision || previous.Desired != desired || previous.Group.ID != groupID || previous.Group.Revision != groupRevision || !slices.Equal(original, targets) {
			return nil, ErrConflict
		}
		if err = auditProfileGroupAssignment(ctx, tx, previous, actor, "replayed"); err != nil {
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
	staged, err := s.stageProfileGroupSource(ctx, tx, actor, permissions, scope, groupScope, sources, profileID, profileRevision, groupID, groupRevision, desired)
	if err != nil {
		return nil, err
	}
	current := make([]string, len(staged.Targets))
	for i, target := range staged.Targets {
		current[i] = target.DeviceID
	}
	if !slices.Equal(current, targets) {
		return nil, ErrConflict
	}
	r := &ProfileGroupAssignment{ID: uuid.NewString(), Scope: scope, GroupScope: groupScope, RequestKey: requestKey, ProfileID: profileID, ProfileRevision: profileRevision, ProfileName: staged.ProfileName, Actor: actor, ActorRevision: permissionRevision, Desired: desired, Group: ProfileGroupSource{ID: staged.Group.ID, Revision: staged.Group.Revision, Name: staged.Group.Name, Rule: staged.Group.Rule}}
	for _, target := range staged.Targets {
		r.Commands = append(r.Commands, ProfileGroupCommand{DeviceID: target.DeviceID, CommandID: target.commandID})
		if err = audit(ctx, tx, scope.TenantID, actor, "apple.profile."+desired, profileID+"/"+target.DeviceID); err != nil {
			return nil, err
		}
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&r.CreatedAt); err != nil {
		return nil, err
	}
	encrypted, err := s.sealProfileGroupAssignment(r)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_profile_group_assignments(id,tenant_id,site_id,request_key,profile_id,profile_revision,actor,actor_revision,desired,created_at,encrypted_intent) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, r.ID, scope.TenantID, scope.SiteID, requestKey, profileID, profileRevision, actor, permissionRevision, desired, r.CreatedAt, encrypted); err != nil {
		return nil, err
	}
	if err = auditProfileGroupAssignment(ctx, tx, r, actor, "created"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

// ProfileGroupAssignmentDetails reads original intent even after catalog or
// group edits. Current scope/assignment authority and the read audit are required.
func (s *Store) ProfileGroupAssignmentDetails(ctx context.Context, actor string, permissions *access.Store, scope Scope, profileID, id string) (*ProfileGroupAssignment, error) {
	if !profileRevisionUUID(profileID) || !profileRevisionUUID(id) {
		return nil, ErrProfileGroup
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = profileGroupAuthority(ctx, tx, permissions, actor, scope); err != nil {
		return nil, err
	}
	r, err := s.readProfileGroupAssignment(tx.QueryRowContext(ctx, `SELECT `+profileGroupColumns+` FROM mdm_apple_profile_group_assignments WHERE tenant_id=$1 AND site_id=$2 AND profile_id=$3 AND id=$4`, scope.TenantID, scope.SiteID, profileID, id))
	if err != nil {
		return nil, err
	}
	if err = auditProfileGroupAssignment(ctx, tx, r, actor, "read"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) ProfileGroupAssignments(ctx context.Context, actor string, permissions *access.Store, scope Scope, profileID, before string) ([]ProfileGroupAssignment, string, error) {
	if !profileRevisionUUID(profileID) || (before != "" && !profileRevisionUUID(before)) {
		return nil, "", ErrProfileGroup
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	if _, err = profileGroupAuthority(ctx, tx, permissions, actor, scope); err != nil {
		return nil, "", err
	}
	var stamp, cursor any
	if before != "" {
		var at time.Time
		if err = tx.QueryRowContext(ctx, `SELECT created_at FROM mdm_apple_profile_group_assignments WHERE tenant_id=$1 AND site_id=$2 AND profile_id=$3 AND id=$4`, scope.TenantID, scope.SiteID, profileID, before).Scan(&at); err != nil {
			return nil, "", notFound(err)
		}
		stamp, cursor = at, before
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+profileGroupColumns+` FROM mdm_apple_profile_group_assignments WHERE tenant_id=$1 AND site_id=$2 AND profile_id=$3 AND ($4::timestamptz IS NULL OR (created_at,id)<($4,$5::uuid)) ORDER BY created_at DESC,id DESC LIMIT 26`, scope.TenantID, scope.SiteID, profileID, stamp, cursor)
	if err != nil {
		return nil, "", err
	}
	items := []ProfileGroupAssignment{}
	for rows.Next() {
		r, err := s.readProfileGroupAssignment(rows)
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
		items, next = items[:25], items[24].ID
	}
	if err = auditProfileGroupAssignment(ctx, tx, &ProfileGroupAssignment{ID: profileID, Scope: scope}, actor, "list"); err != nil {
		return nil, "", err
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	return items, next, nil
}
