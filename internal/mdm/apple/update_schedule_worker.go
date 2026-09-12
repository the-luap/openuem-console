package apple

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type UpdateScheduleProgress struct{ Processed, Activated, Waiting, Blocked, Expired, Failed int }

// ProcessDueUpdateSchedules is a bounded maintenance entry point. Each selected
// record is independent and runs under its original creator's current authority.
func (s *Store) ProcessDueUpdateSchedules(ctx context.Context, permissions *access.Store, sources inventory.DeviceSources, limit int) (UpdateScheduleProgress, error) {
	progress := UpdateScheduleProgress{}
	if permissions == nil {
		return progress, access.ErrDenied
	}
	if limit < 1 || limit > 25 {
		return progress, ErrUpdateSchedule
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM mdm_apple_update_schedules WHERE phase IN ('scheduled','waiting') AND LEAST(next_attempt_at,expires_at)<=clock_timestamp() ORDER BY LEAST(next_attempt_at,expires_at),id LIMIT $1`, limit)
	if err != nil {
		return progress, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return progress, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return progress, err
	}
	var firstError error
	for _, id := range ids {
		phase, err := s.processUpdateSchedule(ctx, permissions, sources, id)
		if err != nil {
			progress.Failed++
			if firstError == nil {
				firstError = err
			}
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if phase == "" {
			continue
		}
		progress.Processed++
		switch phase {
		case "activated":
			progress.Activated++
		case "waiting":
			progress.Waiting++
		case "blocked":
			progress.Blocked++
		case "expired":
			progress.Expired++
		}
	}
	return progress, firstError
}

func (s *Store) processUpdateSchedule(ctx context.Context, permissions *access.Store, sources inventory.DeviceSources, id string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	before, err := s.scanUpdateSchedule(tx.QueryRowContext(ctx, `SELECT `+updateScheduleColumns+` FROM mdm_apple_update_schedules WHERE id=$1`, id))
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	// Match cancellation's lock order. Even denied authority retains the shared
	// permission lock while its old scheduled intent is retired.
	authorizationErr := updatePlanAuthority(ctx, tx, permissions, before.Actor, before.Scope, access.ManageUpdates)
	if authorizationErr != nil && !errors.Is(authorizationErr, access.ErrDenied) && !errors.Is(authorizationErr, ErrNotFound) {
		return "", authorizationErr
	}
	r, err := s.scanUpdateSchedule(tx.QueryRowContext(ctx, `SELECT `+updateScheduleColumns+` FROM mdm_apple_update_schedules WHERE id=$1 AND phase IN ('scheduled','waiting') FOR UPDATE SKIP LOCKED`, id))
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if updateSchedulePurpose(before) != updateSchedulePurpose(r) || !bytes.Equal(before.encryptedIntent, r.encryptedIntent) {
		return "", ErrUpdateScheduleIntegrity
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return "", err
	}
	if now.Before(r.CreatedAt) || now.Before(r.UpdatedAt) {
		return "", ErrUpdateScheduleIntegrity
	}
	if now.Before(r.ExpiresAt) && (now.Before(r.NotBefore) || now.Before(r.NextAttemptAt)) {
		return "", nil
	}
	phase, reason := "", ""
	switch {
	case !now.Before(r.ExpiresAt):
		phase, reason = "expired", "activation_window_expired"
	case errors.Is(authorizationErr, access.ErrDenied):
		phase, reason = "blocked", "authority_changed"
	case errors.Is(authorizationErr, ErrNotFound):
		phase, reason = "blocked", "scope_changed"
	case sources != r.sources:
		phase, reason = "blocked", "sources_changed"
	default:
		var revision int64
		if err = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT revision FROM uem_access_revisions WHERE user_id=$1),0)`, r.Actor).Scan(&revision); err != nil {
			return "", err
		}
		if revision != r.ActorRevision {
			phase, reason = "blocked", "authority_changed"
		}
	}
	if phase != "" {
		if err = s.finishUpdateScheduleAttempt(ctx, tx, r, phase, reason, now); err != nil {
			return "", err
		}
		if err = tx.Commit(); err != nil {
			return "", err
		}
		return phase, nil
	}
	if _, err = tx.ExecContext(ctx, `SAVEPOINT apple_update_activation`); err != nil {
		return "", err
	}
	original := *r
	receipt, activationErr := s.assignUpdatePlanGroupTransaction(ctx, tx, r.Actor, permissions, r.Scope, sources, r.Plan.ID, r.Plan.Revision, r.Group.ID, r.Group.Revision, r.activationKey, r.Targets)
	if activationErr == nil {
		if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return "", err
		}
		if now.Before(r.UpdatedAt) || now.Before(r.NotBefore) {
			return "", ErrUpdateScheduleIntegrity
		}
		if now.Before(r.ExpiresAt) {
			r.AssignmentID = receipt.ID
			if err = s.finishUpdateScheduleAttempt(ctx, tx, r, "activated", "", now); err != nil {
				return "", err
			}
			if !matchesUpdateScheduleAssignment(r, receipt) {
				return "", ErrUpdateScheduleIntegrity
			}
			// The final audit can wait too. Expiry rolls back the state transition,
			// receipt, all device policy changes and their notifications together.
			if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				return "", err
			}
			if now.Before(r.UpdatedAt) {
				return "", ErrUpdateScheduleIntegrity
			}
			if now.Before(r.ExpiresAt) {
				if err = tx.Commit(); err != nil {
					return "", err
				}
				return "activated", nil
			}
		}
	}
	if _, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT apple_update_activation`); err != nil {
		return "", err
	}
	*r = original
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return "", err
	}
	if now.Before(r.UpdatedAt) {
		return "", ErrUpdateScheduleIntegrity
	}
	if !now.Before(r.ExpiresAt) {
		phase, reason = "expired", "activation_window_expired"
	} else {
		switch {
		case errors.Is(activationErr, access.ErrDenied):
			phase, reason = "blocked", "authority_changed"
		case errors.Is(activationErr, ErrConflict), errors.Is(activationErr, ErrUpdateExceptionActive), errors.Is(activationErr, inventory.ErrGroupConflict), errors.Is(activationErr, inventory.ErrGroupInvalid), errors.Is(activationErr, inventory.ErrGroupSnapshotLarge):
			phase, reason = "blocked", "review_changed"
		case errors.Is(activationErr, ErrNotFound), errors.Is(activationErr, inventory.ErrNotFound), errors.Is(activationErr, ErrUnauthorized), errors.Is(activationErr, ErrUpdatePlanIntegrity), errors.Is(activationErr, ErrUpdatePlanGroupIntegrity), errors.Is(activationErr, ErrUpdateExceptionIntegrity):
			phase, reason = "blocked", "source_unavailable"
		default:
			var pg *pgconn.PgError
			if errors.As(activationErr, &pg) && (pg.Code == "40001" || pg.Code == "40P01" || pg.Code == "55P03") {
				phase, reason = "waiting", "temporarily_unavailable"
			} else {
				return "", activationErr
			}
		}
	}
	if err = s.finishUpdateScheduleAttempt(ctx, tx, r, phase, reason, now); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return phase, nil
}

func (s *Store) finishUpdateScheduleAttempt(ctx context.Context, tx *sql.Tx, r *updateStoredSchedule, phase, reason string, now time.Time) error {
	r.Phase, r.Reason, r.UpdatedAt = phase, reason, now
	r.Revision++
	r.Attempts++
	r.CompletedAt = &r.UpdatedAt
	if phase == "waiting" {
		r.CompletedAt = nil
		r.NextAttemptAt = now.Add(time.Minute)
	}
	return s.writeUpdateSchedule(ctx, tx, r, "apple-update-scheduler")
}

func (s *Store) RunUpdateSchedules(ctx context.Context, permissions *access.Store, sources inventory.DeviceSources, logger *slog.Logger) {
	runAppleUpdateSchedules(ctx, time.Minute, 30*time.Second, func(pass context.Context, limit int) (UpdateScheduleProgress, error) {
		return s.ProcessDueUpdateSchedules(pass, permissions, sources, limit)
	}, logger)
}
func runAppleUpdateSchedules(ctx context.Context, interval, timeout time.Duration, process func(context.Context, int) (UpdateScheduleProgress, error), logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	for ctx.Err() == nil {
		pass, cancel := context.WithTimeout(ctx, timeout)
		_, err := process(pass, 25)
		cancel()
		// SQL errors can contain protected intent. Log no source or underlying error.
		if err != nil && ctx.Err() == nil {
			logger.Error("Apple update schedule processing failed")
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
