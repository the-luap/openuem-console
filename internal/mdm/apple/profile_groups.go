package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrProfileGroup = errors.New("invalid Apple profile group selection")
var ErrProfileGroupIntegrity = errors.New("Apple profile group receipt is unavailable")

type ProfileGroupProfile struct {
	ID       string `json:"-" xml:"-" yaml:"-"`
	Name     string `json:"-" xml:"-" yaml:"-"`
	Revision int    `json:"-" xml:"-" yaml:"-"`
}

func (ProfileGroupProfile) String() string     { return "[protected Apple group profile]" }
func (v ProfileGroupProfile) GoString() string { return v.String() }

// ProfileForGroup reads only current catalog metadata for the group chooser.
// Assignment authority, scope and the read audit share one bounded transaction.
func (s *Store) ProfileForGroup(ctx context.Context, actor string, permissions *access.Store, scope Scope, profileID string, revision int) (*ProfileGroupProfile, error) {
	if !profileRevisionUUID(profileID) || revision < 1 || revision > 2147483647 {
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
	p := &ProfileGroupProfile{}
	var payloadScope string
	if err = tx.QueryRowContext(ctx, `SELECT id,name,revision,payload_scope FROM mdm_apple_profiles WHERE tenant_id=$1 AND id=$2 FOR SHARE`, scope.TenantID, profileID).Scan(&p.ID, &p.Name, &p.Revision, &payloadScope); err != nil {
		return nil, notFound(err)
	}
	if p.Revision != revision {
		return nil, ErrConflict
	}
	if payloadScope != "System" {
		return nil, ErrProfilePrerequisite
	}
	if err = auditProfileGroupAssignment(ctx, tx, &ProfileGroupAssignment{ID: profileID, Scope: scope}, actor, "catalog"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}

type ProfileGroupTarget struct {
	commandID string
	DeviceID  string                `json:"-" xml:"-" yaml:"-"`
	Entry     inventory.DeviceEntry `json:"-" xml:"-" yaml:"-"`
	Reason    string                `json:"-" xml:"-" yaml:"-"`
}

type ProfileGroupPreview struct {
	Group           inventory.DeviceGroup `json:"-" xml:"-" yaml:"-"`
	ProfileID       string                `json:"-" xml:"-" yaml:"-"`
	ProfileName     string                `json:"-" xml:"-" yaml:"-"`
	ProfileRevision int                   `json:"-" xml:"-" yaml:"-"`
	Desired         string                `json:"-" xml:"-" yaml:"-"`
	Targets         []ProfileGroupTarget  `json:"-" xml:"-" yaml:"-"`
	Excluded        []ProfileGroupTarget  `json:"-" xml:"-" yaml:"-"`
}

func (ProfileGroupTarget) String() string      { return "[protected Apple profile group target]" }
func (v ProfileGroupTarget) GoString() string  { return v.String() }
func (ProfileGroupPreview) String() string     { return "[protected Apple profile group preview]" }
func (v ProfileGroupPreview) GoString() string { return v.String() }

// PreviewProfileGroup evaluates the complete bounded site group against the
// current profile and admission rules. The admission probe is rolled back before
// the read audits commit: no device commands or resource claims become visible.
// Native IDs determine evaluation order, including conflicts between members.
func (s *Store) PreviewProfileGroup(ctx context.Context, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, profileID string, profileRevision int, groupID string, groupRevision int, desired string) (*ProfileGroupPreview, error) {
	if permissions == nil || scope.TenantID <= 0 || scope.SiteID <= 0 {
		return nil, access.ErrDenied
	}
	if !sources.Apple || !profileRevisionUUID(profileID) || profileRevision < 1 || profileRevision > 2147483647 || (desired != "installed" && desired != "removed") {
		return nil, ErrProfileGroup
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	permissionScope := access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}
	if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.AssignProfiles, permissionScope); err != nil {
		return nil, err
	}
	preview, err := s.stageProfileGroup(ctx, tx, actor, permissions, scope, sources, profileID, profileRevision, groupID, groupRevision, desired)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT apple_profile_group_preview`); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `RELEASE SAVEPOINT apple_profile_group_preview`); err != nil {
		return nil, err
	}
	details, err := json.Marshal(map[string]any{"site_id": scope.SiteID, "result": "success", "targets": len(preview.Targets), "excluded": len(preview.Excluded)})
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,details) VALUES($1,$2,'apple.profile.group.preview',$3,$4)`, scope.TenantID, actor, profileID, details); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return preview, nil
}

// stageProfileGroup leaves the successful admission probes within one savepoint.
// Preview rolls that work back; confirmed admission must match the reviewed
// targets before retaining it. Callers hold current assignment authority.
func (s *Store) stageProfileGroup(ctx context.Context, tx *sql.Tx, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, profileID string, profileRevision int, groupID string, groupRevision int, desired string) (*ProfileGroupPreview, error) {
	permissionScope := access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}
	group, err := inventory.DeviceGroupSnapshotTransaction(ctx, tx, permissions, actor, permissionScope, sources, groupID, groupRevision)
	if err != nil {
		return nil, err
	}
	p, err := s.scanProfile(tx.QueryRowContext(ctx, `SELECT `+profileColumns+` FROM mdm_apple_profiles WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, scope.TenantID, profileID))
	if err != nil {
		return nil, err
	}
	defer clear(p.Payload)
	if p.Revision != profileRevision {
		return nil, ErrConflict
	}
	if p.Scope != "System" {
		return nil, ErrProfilePrerequisite
	}
	preview := &ProfileGroupPreview{Group: group.Group, ProfileID: p.ID, ProfileName: p.Name, ProfileRevision: p.Revision, Desired: desired, Targets: []ProfileGroupTarget{}, Excluded: []ProfileGroupTarget{}}
	candidates, excluded, err := nativeAppleGroupCandidates(ctx, tx, scope, group.Entries)
	if err != nil {
		return nil, err
	}
	preview.Excluded = excluded
	if _, err = tx.ExecContext(ctx, `SAVEPOINT apple_profile_group_preview`); err != nil {
		return nil, err
	}
	for _, target := range candidates {
		if _, err = tx.ExecContext(ctx, `SAVEPOINT apple_profile_group_target`); err != nil {
			return nil, err
		}
		d, readErr := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE tenant_id=$1 AND site_id=$2 AND id=$3 FOR UPDATE`, scope.TenantID, scope.SiteID, target.DeviceID))
		if readErr == nil {
			readErr = s.assign(ctx, tx, d, p, desired)
		}
		if readErr != nil {
			if _, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT apple_profile_group_target`); err != nil {
				return nil, err
			}
			switch {
			case errors.Is(readErr, ErrNotFound):
				target.Reason = "apple_channel_unavailable"
			case errors.Is(readErr, ErrProfilePrerequisite):
				target.Reason = "profile_prerequisite"
			case errors.Is(readErr, ErrADEPlatformSSO):
				target.Reason = "ade_owned"
			default:
				return nil, readErr
			}
			preview.Excluded = append(preview.Excluded, target)
		} else {
			kind := "InstallProfile"
			if desired == "removed" {
				kind = "RemoveProfile"
			}
			if err = tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_commands WHERE tenant_id=$1 AND device_id=$2 AND profile_id=$3 AND profile_revision=$4 AND status='queued' AND request_type=$5`, scope.TenantID, target.DeviceID, p.ID, p.Revision, kind).Scan(&target.commandID); err != nil {
				return nil, err
			}
			preview.Targets = append(preview.Targets, target)
		}
		if _, err = tx.ExecContext(ctx, `RELEASE SAVEPOINT apple_profile_group_target`); err != nil {
			return nil, err
		}
	}
	return preview, nil
}
