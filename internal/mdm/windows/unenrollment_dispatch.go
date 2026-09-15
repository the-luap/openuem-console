package windows

import (
	"context"
	"database/sql"

	"github.com/open-uem/openuem-console/internal/security/access"
)

// An acknowledged Exec is not a disconnection report. Hold subsequent commands
// until the request is explicitly reviewed or Windows retires the enrollment.
func (s *Store) unenrollmentHoldsDelivery(ctx context.Context, tx *sql.Tx, scope access.Scope, deviceID string) (bool, error) {
	commands, err := s.unenrollmentCommands(ctx, tx, scope, deviceID, 0, 0)
	if err != nil {
		return false, err
	}
	for _, c := range commands {
		if c.DeliveredAt == nil {
			continue
		}
		_, release, err := s.unenrollmentForCommand(ctx, tx, c)
		if err != nil {
			return false, err
		}
		if err = s.checkCSPIntegrity(c); err != nil {
			return false, err
		}
		if release == nil {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) cspCommandEligibility(ctx context.Context, tx *sql.Tx, c *cspStoredCommand) (string, error) {
	if c.UnenrollmentRequestID != "" {
		_, release, err := s.unenrollmentForCommand(ctx, tx, c)
		if err != nil {
			return "", err
		}
		if release != nil {
			return "unenrollment_released", nil
		}
		return "", nil
	}
	return s.updateCommandEligibility(ctx, tx, c)
}
