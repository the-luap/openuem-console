package apple

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

type OSObservation struct {
	Version    string    `json:"-" xml:"-" yaml:"-"`
	Build      string    `json:"-" xml:"-" yaml:"-"`
	Source     string    `json:"-" xml:"-" yaml:"-"`
	RecordedAt time.Time `json:"-" xml:"-" yaml:"-"`
}
type UpdateAssessment struct {
	Scope                Scope                     `json:"-" xml:"-" yaml:"-"`
	DeviceID             string                    `json:"-" xml:"-" yaml:"-"`
	Availability         string                    `json:"-" xml:"-" yaml:"-"`
	Observation          *OSObservation            `json:"-" xml:"-" yaml:"-"`
	Policy               *UpdatePolicy             `json:"-" xml:"-" yaml:"-"`
	PolicyToken          string                    `json:"-" xml:"-" yaml:"-"`
	Deadline             *UpdateDeadlineAssessment `json:"-" xml:"-" yaml:"-"`
	Exception            *UpdateException          `json:"-" xml:"-" yaml:"-"`
	ExceptionActive      bool                      `json:"-" xml:"-" yaml:"-"`
	PolicyHasError       bool                      `json:"-" xml:"-" yaml:"-"`
	PolicyErrorTruncated bool                      `json:"-" xml:"-" yaml:"-"`
	Compliance           string                    `json:"-" xml:"-" yaml:"-"`
	Reason               string                    `json:"-" xml:"-" yaml:"-"`
	AssessedAt           time.Time                 `json:"-" xml:"-" yaml:"-"`
}

func (OSObservation) String() string        { return "[protected Apple OS observation]" }
func (v OSObservation) GoString() string    { return v.String() }
func (UpdateAssessment) String() string     { return "[protected Apple update assessment]" }
func (v UpdateAssessment) GoString() string { return v.String() }

// A cohort additionally supplies its admission time. An individual assessment
// concerns the current policy and does not attribute a result to an assignment.
func assessUpdateOS(availability string, observation *OSObservation, targetVersion, targetBuild string, after, now time.Time) (string, string) {
	switch {
	case availability != "available":
		return "unverified", "device_unavailable"
	case observation == nil:
		return "unverified", "no_report"
	case observation.RecordedAt.After(now):
		return "unverified", "future_report"
	case !after.IsZero() && observation.RecordedAt.Before(after):
		return "unverified", "before_assignment"
	case now.Sub(observation.RecordedAt) > 24*time.Hour:
		return "unverified", "stale_report"
	case !versionPattern.MatchString(observation.Version):
		return "unverified", "invalid_report"
	}
	comparison := CompareVersions(observation.Version, targetVersion)
	if comparison > 0 || (comparison == 0 && targetBuild == "") {
		return "target_reported", ""
	}
	if comparison < 0 {
		return "update_required", ""
	}
	if !updatePlanBuild.MatchString(observation.Build) {
		return "unverified", "missing_build"
	}
	if observation.Build == targetBuild {
		return "target_reported", ""
	}
	return "update_required", ""
}

// AssessDeviceUpdate reads current authority, site ownership, policy and packet
// OS evidence in one bounded audited transaction. Scope may be an organization
// or an exact site; a moved device is rechecked after acquiring its site lock.
func (s *Store) AssessDeviceUpdate(ctx context.Context, actor string, permissions *access.Store, scope Scope, id string) (*UpdateAssessment, error) {
	if permissions == nil || scope.Validate() != nil {
		return nil, access.ErrDenied
	}
	if !profileRevisionUUID(id) {
		return nil, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ReadDevices, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}); err != nil {
		return nil, err
	}
	var tenant, site int
	if err = tx.QueryRowContext(ctx, `SELECT id FROM tenants WHERE id=$1 FOR SHARE`, scope.TenantID).Scan(&tenant); err != nil {
		return nil, notFound(err)
	}
	if err = tx.QueryRowContext(ctx, `SELECT site_id FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND ($3=0 OR site_id=$3)`, id, scope.TenantID, scope.SiteID).Scan(&site); err != nil {
		return nil, notFound(err)
	}
	if site < 1 {
		return nil, ErrNotFound
	}
	{
		var locked int
		if err = tx.QueryRowContext(ctx, `SELECT id FROM sites WHERE id=$1 AND tenant_sites=$2 FOR SHARE`, site, scope.TenantID).Scan(&locked); err != nil {
			return nil, notFound(err)
		}
		if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ReadDevices, access.Scope{TenantID: scope.TenantID, SiteID: site}); err != nil {
			return nil, err
		}
	}
	var enrolled bool
	var expiry time.Time
	if err = tx.QueryRowContext(ctx, `SELECT status='enrolled',certificate_expires_at FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR SHARE`, id, scope.TenantID, site).Scan(&enrolled, &expiry); err != nil {
		return nil, notFound(err)
	}
	assessment := &UpdateAssessment{Scope: Scope{TenantID: scope.TenantID, SiteID: site}, DeviceID: id, Availability: "available"}
	if !enrolled {
		assessment.Availability = "not_managed"
	}
	assessment.Policy, assessment.PolicyHasError, assessment.PolicyErrorTruncated, err = currentUpdatePolicyState(ctx, tx, id, true)
	if err != nil {
		return nil, err
	}
	if assessment.Policy != nil && (!versionPattern.MatchString(assessment.Policy.TargetVersion) || (assessment.Policy.TargetBuild != "" && !updatePlanBuild.MatchString(assessment.Policy.TargetBuild))) {
		return nil, ErrUpdatePlanGroupIntegrity
	}
	assessment.PolicyToken = updatePolicyGroupToken(assessment.Scope, id, assessment.Policy)
	observation := &OSObservation{}
	err = tx.QueryRowContext(ctx, `SELECT version,build,source,recorded_at FROM mdm_apple_os_observations WHERE device_id=$1`, id).Scan(&observation.Version, &observation.Build, &observation.Source, &observation.RecordedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		assessment.Observation = observation
	}
	zone, err := currentTimeZoneObservation(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	assessment.Exception, err = s.currentUpdateException(ctx, tx, assessment.Scope, id)
	if err != nil {
		return nil, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&assessment.AssessedAt); err != nil {
		return nil, err
	}
	if assessment.Availability == "available" && !expiry.After(assessment.AssessedAt) {
		assessment.Availability = "identity_expired"
	}
	if assessment.Exception != nil && assessment.Exception.CreatedAt.After(assessment.AssessedAt) {
		return nil, ErrUpdateExceptionIntegrity
	}
	assessment.ExceptionActive = assessment.Exception.Active(assessment.AssessedAt)
	assessment.Deadline = assessUpdateDeadline(assessment.Availability == "available", assessment.Policy, zone, assessment.AssessedAt)
	if assessment.Policy != nil {
		result, reason := assessUpdateOS(assessment.Availability, assessment.Observation, assessment.Policy.TargetVersion, assessment.Policy.TargetBuild, time.Time{}, assessment.AssessedAt)
		assessment.Reason = reason
		switch {
		case assessment.Availability != "available":
			assessment.Compliance = "not_managed"
		case result == "target_reported":
			assessment.Compliance = "compliant"
		case result == "unverified":
			assessment.Compliance = "unknown"
		default:
			assessment.Compliance = "update_required"
		}
	}
	if err = auditUpdatePlan(ctx, tx, assessment.Scope, actor, "device.assessment", id, 0); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return assessment, nil
}
