package apple

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

type UpdateGroupRemovalTarget struct {
	Selection             UpdatePlanGroupSelection `json:"-" xml:"-" yaml:"-"`
	Name                  string                   `json:"-" xml:"-" yaml:"-"`
	CurrentPolicy         *UpdatePolicy            `json:"-" xml:"-" yaml:"-"`
	Reason                string                   `json:"-" xml:"-" yaml:"-"`
	NotificationAvailable bool                     `json:"-" xml:"-" yaml:"-"`
	device                *Device
}

type UpdateGroupRemovalPreview struct {
	Assignment UpdatePlanGroupAssignment  `json:"-" xml:"-" yaml:"-"`
	Devices    []UpdateGroupRemovalTarget `json:"-" xml:"-" yaml:"-"`
	AssessedAt time.Time                  `json:"-" xml:"-" yaml:"-"`
}

func (UpdateGroupRemovalTarget) String() string      { return "[protected Apple update removal target]" }
func (v UpdateGroupRemovalTarget) GoString() string  { return v.String() }
func (UpdateGroupRemovalPreview) String() string     { return "[protected Apple update removal preview]" }
func (v UpdateGroupRemovalPreview) GoString() string { return v.String() }

// PreviewUpdateGroupRemoval reviews only the original receipt's native targets.
// Later group membership, plan edits and catalog availability do not expand it.
func (s *Store) PreviewUpdateGroupRemoval(ctx context.Context, actor string, permissions *access.Store, scope Scope, planID, assignmentID string) (*UpdateGroupRemovalPreview, error) {
	if !profileRevisionUUID(planID) || !profileRevisionUUID(assignmentID) {
		return nil, ErrUpdatePlanGroup
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
	p, err := s.inspectUpdateGroupRemoval(ctx, tx, scope, planID, assignmentID, false)
	if err != nil {
		return nil, err
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "group.removal.preview", assignmentID, p.Assignment.Plan.Revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}

func updateGroupRemovalAuthority(ctx context.Context, tx *sql.Tx, permissions *access.Store, actor string, scope Scope) error {
	if err := updatePlanAuthority(ctx, tx, permissions, actor, scope, access.ManageUpdates); err != nil {
		return err
	}
	return permissions.AuthorizeTransaction(ctx, tx, actor, access.ReadDevices, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID})
}

func (s *Store) inspectUpdateGroupRemoval(ctx context.Context, tx *sql.Tx, scope Scope, planID, assignmentID string, admitting bool) (*UpdateGroupRemovalPreview, error) {
	r, err := s.scanUpdateGroupAssignment(tx.QueryRowContext(ctx, `SELECT `+updateGroupColumns+` FROM mdm_apple_update_group_assignments WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4`, assignmentID, scope.TenantID, scope.SiteID, planID))
	if err != nil {
		return nil, err
	}
	p := &UpdateGroupRemovalPreview{Assignment: *r, Devices: make([]UpdateGroupRemovalTarget, 0, len(r.Commands))}
	lock := " FOR SHARE"
	if admitting {
		lock = " FOR UPDATE"
	}
	for _, command := range r.Commands {
		target := UpdateGroupRemovalTarget{Selection: UpdatePlanGroupSelection{DeviceID: command.Selection.DeviceID}, Reason: "unavailable"}
		d := &Device{ID: target.Selection.DeviceID, TenantID: scope.TenantID, SiteID: scope.SiteID}
		var enrolled bool
		// Removal needs no application/security inventory or release catalog. Bound
		// the few capability fields before loading the original cohort into memory.
		err = tx.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(name)<=512 THEN name ELSE '' END,status='enrolled',certificate_expires_at,CASE WHEN octet_length(model)<=255 THEN model ELSE '' END,CASE WHEN octet_length(os_version)<=32 THEN os_version ELSE '' END,CASE WHEN octet_length(platform)<=32 THEN platform ELSE 'unknown' END,supervised,supervised_reported FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND site_id=$3`+lock, d.ID, scope.TenantID, scope.SiteID).Scan(&d.Name, &enrolled, &d.CertificateExpiresAt, &d.Model, &d.OSVersion, &d.OSFamily, &d.Supervised, &d.SupervisedReported)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if err == nil {
			target.Name, target.device = d.Name, d
			target.Reason = "not_managed"
			if enrolled {
				d.Status, target.Reason = "enrolled", ""
			}
			target.NotificationAvailable = d.Capabilities().DeclarativeManagement
			target.CurrentPolicy, err = currentUpdateGroupPolicy(ctx, tx, d.ID)
			if err != nil {
				return nil, err
			}
		}
		p.Devices = append(p.Devices, target)
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&p.AssessedAt); err != nil {
		return nil, err
	}
	originalPolicy := r.Plan.Definition.Policy()
	for i := range p.Devices {
		target := &p.Devices[i]
		if target.Reason != "" {
			continue
		}
		switch {
		case !target.device.CertificateExpiresAt.After(p.AssessedAt):
			target.Reason = "identity_expired"
		case target.CurrentPolicy == nil:
			target.Reason = "absent"
		case updatePolicyGroupToken(scope, target.Selection.DeviceID, target.CurrentPolicy) != updatePolicyGroupToken(scope, target.Selection.DeviceID, &originalPolicy):
			target.Reason = "different"
		default:
			target.Selection.PolicyToken = updateGroupRemovalToken(scope, target.Selection.DeviceID, target.CurrentPolicy, target.NotificationAvailable)
		}
	}
	return p, nil
}

// A capability change must trigger another review when it changes whether this
// server can notify the device about removal. OS progress otherwise stays separate.
func updateGroupRemovalToken(scope Scope, id string, policy *UpdatePolicy, notify bool) string {
	return digest([]byte("openuem/apple/update-group/removal-review/v1/" + updatePolicyGroupToken(scope, id, policy) + "/" + strconv.FormatBool(notify)))
}

func updateGroupRemovalSelection(p *UpdateGroupRemovalPreview) []UpdatePlanGroupSelection {
	selection := []UpdatePlanGroupSelection{}
	for _, target := range p.Devices {
		if target.Reason == "" {
			selection = append(selection, target.Selection)
		}
	}
	return selection
}
