package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrUpdatePlanGroup = errors.New("invalid Apple update plan group selection")
var ErrUpdatePlanGroupIntegrity = errors.New("Apple update plan group state is unavailable")

type UpdatePlanGroupSelection struct {
	DeviceID    string `json:"-" xml:"-" yaml:"-"`
	PolicyToken string `json:"-" xml:"-" yaml:"-"`
}
type UpdatePlanGroupTarget struct {
	Selection     UpdatePlanGroupSelection `json:"-" xml:"-" yaml:"-"`
	Entry         inventory.DeviceEntry    `json:"-" xml:"-" yaml:"-"`
	CurrentPolicy *UpdatePolicy            `json:"-" xml:"-" yaml:"-"`
}
type UpdatePlanGroupPreview struct {
	Plan     UpdatePlan              `json:"-" xml:"-" yaml:"-"`
	Group    inventory.DeviceGroup   `json:"-" xml:"-" yaml:"-"`
	Targets  []UpdatePlanGroupTarget `json:"-" xml:"-" yaml:"-"`
	Excluded []ProfileGroupTarget    `json:"-" xml:"-" yaml:"-"`
}

func (UpdatePlanGroupSelection) String() string     { return "[protected Apple update group selection]" }
func (v UpdatePlanGroupSelection) GoString() string { return v.String() }
func (UpdatePlanGroupTarget) String() string        { return "[protected Apple update group target]" }
func (v UpdatePlanGroupTarget) GoString() string    { return v.String() }
func (UpdatePlanGroupPreview) String() string       { return "[protected Apple update group preview]" }
func (v UpdatePlanGroupPreview) GoString() string   { return v.String() }

type updatePolicyGroupState struct{ TargetVersion, TargetBuild, Deadline, DetailsURL string }

// The token covers configured policy values, including absence. Progress and
// observation timestamps cannot invalidate a reviewed configuration. Binding the
// native identity prevents transferring a token to another target or scope.
func updatePolicyGroupToken(scope Scope, id string, p *UpdatePolicy) string {
	var state *updatePolicyGroupState
	if p != nil {
		state = &updatePolicyGroupState{p.TargetVersion, p.TargetBuild, p.Deadline, p.DetailsURL}
	}
	plain, _ := json.Marshal(state)
	defer clear(plain)
	return digest(append([]byte(fmt.Sprintf("openuem/apple/update-group/current/v1/%d/%d/%s/", scope.TenantID, scope.SiteID, id)), plain...))
}

func currentUpdateGroupPolicy(ctx context.Context, tx *sql.Tx, id string) (*UpdatePolicy, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(target_version)+octet_length(target_build)+octet_length(deadline)+octet_length(details_url)<=8192 THEN jsonb_build_object('TargetVersion',target_version,'TargetBuild',target_build,'Deadline',deadline,'DetailsURL',details_url) ELSE NULL END FROM mdm_apple_update_policies WHERE device_id=$1`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var fields updatePolicyGroupState
	if len(raw) == 0 || json.Unmarshal(raw, &fields) != nil {
		return nil, ErrUpdatePlanGroupIntegrity
	}
	return &UpdatePolicy{DeviceID: id, TargetVersion: fields.TargetVersion, TargetBuild: fields.TargetBuild, Deadline: fields.Deadline, DetailsURL: fields.DetailsURL}, nil
}

// PreviewUpdatePlanGroup reviews current eligibility and configured policies
// without writing device work. Confirmation must retain both source revisions
// and every eligible native target's current policy token.
func (s *Store) PreviewUpdatePlanGroup(ctx context.Context, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, planID string, planRevision int, groupID string, groupRevision int) (*UpdatePlanGroupPreview, error) {
	if !sources.Apple || !profileRevisionUUID(planID) || planRevision < 1 || planRevision > 2147483647 {
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
	preview, err := s.inspectUpdatePlanGroup(ctx, tx, actor, permissions, scope, sources, planID, planRevision, groupID, groupRevision, false)
	if err != nil {
		return nil, err
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "group.preview", planID, planRevision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return preview, nil
}

// inspectUpdatePlanGroup keeps the plan, group, catalog and current device/policy
// inputs stable within one transaction. Admission uses exclusive device locks.
func (s *Store) inspectUpdatePlanGroup(ctx context.Context, tx *sql.Tx, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, planID string, planRevision int, groupID string, groupRevision int, admitting bool) (*UpdatePlanGroupPreview, error) {
	p, err := s.scanUpdatePlan(tx.QueryRowContext(ctx, `SELECT `+updatePlanColumns+` FROM `+updatePlanCurrentJoin+` WHERE p.tenant_id=$1 AND p.site_id=$2 AND p.id=$3 FOR SHARE OF p`, scope.TenantID, scope.SiteID, planID))
	if err != nil {
		return nil, err
	}
	if p.Revision != planRevision || p.Definition.Archived {
		return nil, ErrConflict
	}
	group, err := inventory.DeviceGroupSnapshotTransaction(ctx, tx, permissions, actor, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, sources, groupID, groupRevision)
	if err != nil {
		return nil, err
	}
	candidates, excluded, err := nativeAppleGroupCandidates(ctx, tx, scope, group.Entries)
	if err != nil {
		return nil, err
	}
	// Decode one bounded, locked catalog for the complete cohort. Refresh cannot
	// change release availability halfway through this inspection.
	var raw []byte
	var fetched *time.Time
	if err = tx.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(document::text)<=8388608 THEN document ELSE NULL END,fetched_at FROM mdm_apple_software_catalog WHERE singleton=true FOR SHARE`).Scan(&raw, &fetched); err != nil {
		return nil, err
	}
	var releases SoftwareCatalog
	if len(raw) == 0 || json.Unmarshal(raw, &releases) != nil {
		return nil, ErrUpdatePlanGroupIntegrity
	}
	now := time.Now()
	fresh := fetched != nil && now.Sub(*fetched) <= 48*time.Hour
	preview := &UpdatePlanGroupPreview{Plan: *p, Group: group.Group, Targets: []UpdatePlanGroupTarget{}, Excluded: excluded}
	policy := p.Definition.Policy()
	lock := " FOR SHARE"
	if admitting {
		lock = " FOR UPDATE"
	}
	for _, candidate := range candidates {
		d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE tenant_id=$1 AND site_id=$2 AND id=$3`+lock, scope.TenantID, scope.SiteID, candidate.DeviceID))
		reason := ""
		if errors.Is(err, ErrNotFound) {
			reason = "apple_channel_unavailable"
		} else if err != nil {
			return nil, err
		}
		if reason == "" {
			if string(d.Family()) != p.Definition.Platform {
				reason = "different_platform"
			} else if ValidateUpdatePolicy(*d, policy) != nil {
				reason = "update_prerequisite"
			}
		}
		if reason == "" && (!fresh || !releases.Supports(*d, policy, now)) {
			reason = "release_unavailable"
		}
		if reason != "" {
			candidate.Reason = reason
			preview.Excluded = append(preview.Excluded, candidate)
			continue
		}
		current, err := currentUpdateGroupPolicy(ctx, tx, d.ID)
		if err != nil {
			return nil, err
		}
		preview.Targets = append(preview.Targets, UpdatePlanGroupTarget{Selection: UpdatePlanGroupSelection{DeviceID: d.ID, PolicyToken: updatePolicyGroupToken(scope, d.ID, current)}, Entry: candidate.Entry, CurrentPolicy: current})
	}
	return preview, nil
}

// UpdatePlanForGroup reads the exact current source for the group chooser under
// current update authority; ordinary plan readers cannot start an assignment.
func (s *Store) UpdatePlanForGroup(ctx context.Context, actor string, permissions *access.Store, scope Scope, id string, revision int) (*UpdatePlan, error) {
	if !profileRevisionUUID(id) || revision < 1 || revision > 2147483647 {
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
	plan, err := s.scanUpdatePlan(tx.QueryRowContext(ctx, `SELECT `+updatePlanColumns+` FROM `+updatePlanCurrentJoin+` WHERE p.tenant_id=$1 AND p.site_id=$2 AND p.id=$3 FOR SHARE OF p`, scope.TenantID, scope.SiteID, id))
	if err != nil {
		return nil, err
	}
	if plan.Revision != revision || plan.Definition.Archived {
		return nil, ErrConflict
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "group.catalog", id, revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return plan, nil
}
