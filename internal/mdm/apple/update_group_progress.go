package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

type UpdateGroupDeviceProgress struct {
	DeviceID           string                    `json:"-" xml:"-" yaml:"-"`
	Name               string                    `json:"-" xml:"-" yaml:"-"`
	Availability       string                    `json:"-" xml:"-" yaml:"-"`
	PolicyState        string                    `json:"-" xml:"-" yaml:"-"`
	CurrentPolicy      *UpdatePolicy             `json:"-" xml:"-" yaml:"-"`
	PolicyHasError     bool                      `json:"-" xml:"-" yaml:"-"`
	NotificationStatus string                    `json:"-" xml:"-" yaml:"-"`
	ReportedVersion    string                    `json:"-" xml:"-" yaml:"-"`
	ReportedBuild      string                    `json:"-" xml:"-" yaml:"-"`
	ReportSource       string                    `json:"-" xml:"-" yaml:"-"`
	RecordedAt         *time.Time                `json:"-" xml:"-" yaml:"-"`
	Result             string                    `json:"-" xml:"-" yaml:"-"`
	Reason             string                    `json:"-" xml:"-" yaml:"-"`
	Deadline           *UpdateDeadlineAssessment `json:"-" xml:"-" yaml:"-"`
}
type UpdateGroupProgressCounts struct {
	Total                       int `json:"-" xml:"-" yaml:"-"`
	TargetReported              int `json:"-" xml:"-" yaml:"-"`
	UpdateRequired              int `json:"-" xml:"-" yaml:"-"`
	Unverified                  int `json:"-" xml:"-" yaml:"-"`
	PolicyMatches               int `json:"-" xml:"-" yaml:"-"`
	PolicyDifferent             int `json:"-" xml:"-" yaml:"-"`
	PolicyAbsent                int `json:"-" xml:"-" yaml:"-"`
	PolicyAttention             int `json:"-" xml:"-" yaml:"-"`
	Unavailable                 int `json:"-" xml:"-" yaml:"-"`
	DeadlineElapsed             int `json:"-" xml:"-" yaml:"-"`
	DeadlinePending             int `json:"-" xml:"-" yaml:"-"`
	DeadlineUnverified          int `json:"-" xml:"-" yaml:"-"`
	UpdateRequiredAfterDeadline int `json:"-" xml:"-" yaml:"-"`
}
type UpdateGroupProgress struct {
	Assignment UpdatePlanGroupAssignment   `json:"-" xml:"-" yaml:"-"`
	AssessedAt time.Time                   `json:"-" xml:"-" yaml:"-"`
	Devices    []UpdateGroupDeviceProgress `json:"-" xml:"-" yaml:"-"`
	Counts     UpdateGroupProgressCounts   `json:"-" xml:"-" yaml:"-"`
}

func (UpdateGroupDeviceProgress) String() string     { return "[protected Apple update device progress]" }
func (v UpdateGroupDeviceProgress) GoString() string { return v.String() }
func (UpdateGroupProgressCounts) String() string     { return "[protected Apple update progress counts]" }
func (v UpdateGroupProgressCounts) GoString() string { return v.String() }
func (UpdateGroupProgress) String() string           { return "[protected Apple update group progress]" }
func (v UpdateGroupProgress) GoString() string       { return v.String() }

func currentUpdatePolicyState(ctx context.Context, tx *sql.Tx, id string, withError bool) (*UpdatePolicy, bool, bool, error) {
	var raw []byte
	var status sql.NullString
	var hasError, errorTruncated bool
	var detail string
	var updated time.Time
	err := tx.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(target_version)+octet_length(target_build)+octet_length(deadline)+octet_length(details_url)<=8192 THEN jsonb_build_object('TargetVersion',target_version,'TargetBuild',target_build,'Deadline',deadline,'DetailsURL',details_url) ELSE NULL END,CASE WHEN octet_length(status)<=64 THEN status ELSE NULL END,error<>'',updated_at,octet_length(error)>8192,CASE WHEN $2 AND octet_length(error)<=8192 THEN error ELSE '' END FROM mdm_apple_update_policies WHERE device_id=$1 FOR SHARE`, id, withError).Scan(&raw, &status, &hasError, &updated, &errorTruncated, &detail)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, false, nil
	}
	if err != nil {
		return nil, false, false, err
	}
	var fields updatePolicyGroupState
	if len(raw) == 0 || !status.Valid || json.Unmarshal(raw, &fields) != nil {
		return nil, false, false, ErrUpdatePlanGroupIntegrity
	}
	return &UpdatePolicy{DeviceID: id, TargetVersion: fields.TargetVersion, TargetBuild: fields.TargetBuild, Deadline: fields.Deadline, DetailsURL: fields.DetailsURL, Status: status.String, Error: detail, UpdatedAt: updated}, hasError, errorTruncated, nil
}

func currentUpdateProgressPolicy(ctx context.Context, tx *sql.Tx, id string) (*UpdatePolicy, bool, error) {
	p, hasError, _, err := currentUpdatePolicyState(ctx, tx, id, false)
	return p, hasError, err
}

func assessUpdateGroupResult(d *UpdateGroupDeviceProgress, plan UpdatePlan, admitted, now time.Time) {
	var observation *OSObservation
	if d.RecordedAt != nil {
		observation = &OSObservation{Version: d.ReportedVersion, Build: d.ReportedBuild, Source: d.ReportSource, RecordedAt: *d.RecordedAt}
	}
	d.Result, d.Reason = assessUpdateOS(d.Availability, observation, plan.Definition.TargetVersion, plan.Definition.TargetBuild, admitted, now)
}

// A report before the estimated deadline cannot establish that the target was
// still missing after it. Other OS/deadline counts remain independent.
func updateRequirementAfterDeadline(d UpdateGroupDeviceProgress) bool {
	return d.Result == "update_required" && d.RecordedAt != nil && d.Deadline != nil && d.Deadline.State == "elapsed" && d.Deadline.Latest != nil && !d.RecordedAt.Before(*d.Deadline.Latest)
}

// UpdatePlanGroupProgress assesses current state for the exact original native
// cohort. It never expands the group, rewrites its receipt or attributes an OS
// installation to an acknowledged declaration notification.
func (s *Store) UpdatePlanGroupProgress(ctx context.Context, actor string, permissions *access.Store, scope Scope, planID, id string) (*UpdateGroupProgress, error) {
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
	if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ReadDevices, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}); err != nil {
		return nil, err
	}
	receipt, err := s.scanUpdateGroupAssignment(tx.QueryRowContext(ctx, `SELECT `+updateGroupColumns+` FROM mdm_apple_update_group_assignments WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4`, id, scope.TenantID, scope.SiteID, planID))
	if err != nil {
		return nil, err
	}
	progress := &UpdateGroupProgress{Assignment: *receipt, Devices: make([]UpdateGroupDeviceProgress, 0, len(receipt.Commands))}
	expires := make([]time.Time, 0, len(receipt.Commands))
	zones := make([]*TimeZoneObservation, 0, len(receipt.Commands))
	for _, command := range receipt.Commands {
		d := UpdateGroupDeviceProgress{DeviceID: command.Selection.DeviceID, Availability: "unavailable", PolicyState: "unknown", NotificationStatus: "unavailable"}
		var enrolled bool
		var expiry time.Time
		var zone *TimeZoneObservation
		var version, build, source, notification sql.NullString
		err = tx.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(d.name)<=512 THEN d.name ELSE '' END,d.status='enrolled',d.certificate_expires_at,o.version,o.build,o.source,o.recorded_at,CASE WHEN octet_length(c.status)<=64 THEN c.status ELSE NULL END FROM mdm_apple_devices d LEFT JOIN mdm_apple_os_observations o ON o.device_id=d.id LEFT JOIN mdm_apple_commands c ON c.id=$4 AND c.device_id=d.id AND c.tenant_id=d.tenant_id AND c.request_type='DeclarativeManagement' WHERE d.id=$1 AND d.tenant_id=$2 AND d.site_id=$3 FOR SHARE OF d`, d.DeviceID, scope.TenantID, scope.SiteID, command.CommandID).Scan(&d.Name, &enrolled, &expiry, &version, &build, &source, &d.RecordedAt, &notification)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if err == nil {
			d.Availability = "available"
			if !enrolled {
				d.Availability = "not_managed"
			}
			d.ReportedVersion, d.ReportedBuild, d.ReportSource = version.String, build.String, source.String
			if notification.Valid {
				d.NotificationStatus = notification.String
			}
			d.CurrentPolicy, d.PolicyHasError, err = currentUpdateProgressPolicy(ctx, tx, d.DeviceID)
			if err != nil {
				return nil, err
			}
			zone, err = currentTimeZoneObservation(ctx, tx, d.DeviceID)
			if err != nil {
				return nil, err
			}
			d.PolicyState = "absent"
			if d.CurrentPolicy != nil {
				d.PolicyState = "different"
				p := receipt.Plan.Definition.Policy()
				if updatePolicyGroupToken(scope, d.DeviceID, d.CurrentPolicy) == updatePolicyGroupToken(scope, d.DeviceID, &p) {
					d.PolicyState = "matches"
				}
			}
		}
		progress.Devices = append(progress.Devices, d)
		expires = append(expires, expiry)
		zones = append(zones, zone)
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&progress.AssessedAt); err != nil {
		return nil, err
	}
	for i := range progress.Devices {
		d := &progress.Devices[i]
		if d.Availability == "available" && !expires[i].After(progress.AssessedAt) {
			d.Availability = "identity_expired"
		}
		assessUpdateGroupResult(d, receipt.Plan, receipt.CreatedAt, progress.AssessedAt)
		originalPolicy := receipt.Plan.Definition.Policy()
		d.Deadline = assessUpdateDeadline(d.Availability == "available", &originalPolicy, zones[i], progress.AssessedAt)
		switch d.Deadline.State {
		case "elapsed":
			progress.Counts.DeadlineElapsed++
			if updateRequirementAfterDeadline(*d) {
				progress.Counts.UpdateRequiredAfterDeadline++
			}
		case "pending":
			progress.Counts.DeadlinePending++
		default:
			progress.Counts.DeadlineUnverified++
		}
		progress.Counts.Total++
		switch d.Result {
		case "target_reported":
			progress.Counts.TargetReported++
		case "update_required":
			progress.Counts.UpdateRequired++
		default:
			progress.Counts.Unverified++
		}
		switch d.PolicyState {
		case "matches":
			progress.Counts.PolicyMatches++
		case "different":
			progress.Counts.PolicyDifferent++
		case "absent":
			progress.Counts.PolicyAbsent++
		}
		if d.Availability != "available" {
			progress.Counts.Unavailable++
		}
		if d.PolicyState == "matches" && (d.PolicyHasError || d.CurrentPolicy.Status == "failed" || d.CurrentPolicy.Status == "unavailable") {
			progress.Counts.PolicyAttention++
		}
	}
	if err = auditUpdatePlan(ctx, tx, scope, actor, "group.progress", receipt.ID, receipt.Plan.Revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return progress, nil
}
