package apple

import (
	"context"
	"database/sql"
	"slices"
	"time"
)

// Authenticated parent and cohort binding is checked before a watch or its
// history is exposed. Archived/edited plan definitions do not replace the
// immutable original assignment. Callers own current authority and scope locks.
func (s *Store) validateUpdateEscalationSource(ctx context.Context, tx *sql.Tx, r *UpdateEscalation) error {
	original, err := s.scanUpdateGroupAssignment(tx.QueryRowContext(ctx, `SELECT `+updateGroupColumns+` FROM mdm_apple_update_group_assignments WHERE id=$1 AND tenant_id=$2 AND site_id=$3 AND plan_id=$4`, r.AssignmentID, r.Scope.TenantID, r.Scope.SiteID, r.PlanID))
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(original.Commands))
	for _, command := range original.Commands {
		ids = append(ids, command.Selection.DeviceID)
	}
	if !slices.Equal(ids, r.original) || r.CreatedAt.Before(original.CreatedAt) {
		return ErrUpdateEscalationIntegrity
	}
	if r.Snapshot != nil {
		if r.Snapshot.AssessedAt.Before(original.CreatedAt) {
			return ErrUpdateEscalationIntegrity
		}
		wall, err := time.Parse("2006-01-02T15:04:05", original.Plan.Definition.Deadline)
		if err != nil {
			return ErrUpdateEscalationIntegrity
		}
		for _, e := range r.Snapshot.Devices {
			if e.Decision.State == "attention" || e.Decision.Reason == "target_reported" {
				result, _ := assessUpdateOS("available", e.Observation, original.Plan.Definition.TargetVersion, original.Plan.Definition.TargetBuild, original.CreatedAt, r.Snapshot.AssessedAt)
				if (e.Decision.State == "attention" && result != "update_required") || (e.Decision.Reason == "target_reported" && result != "target_reported") {
					return ErrUpdateEscalationIntegrity
				}
			}
			if e.Deadline != nil && e.Deadline.Latest != nil {
				if e.Deadline.Earliest == nil || e.Deadline.Earliest.Before(wall.Add(-48*time.Hour)) || e.Deadline.Latest.After(wall.Add(48*time.Hour)) {
					return ErrUpdateEscalationIntegrity
				}
			}
		}
	}
	r.Assignment = original
	return nil
}
