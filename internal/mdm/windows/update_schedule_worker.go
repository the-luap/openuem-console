package windows

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

var errUpdateGroupSourcesChanged = errors.New("Windows group inventory sources changed")

var errUpdateActivationExpired = errors.New("Windows update activation window expired")

type UpdateScheduleProgress struct {
	Processed int
	Activated int
	Waiting   int
	Blocked   int
	Expired   int
	Failed    int
}

// ProcessDueUpdateSchedules is a bounded maintenance entry point, not a console
// API. Each schedule uses its original creator's live authority. One malformed
// record does not prevent processing other records selected in the same batch.
func (s *Store) ProcessDueUpdateSchedules(ctx context.Context, limit int) (UpdateScheduleProgress, error) {
	progress := UpdateScheduleProgress{}
	if s == nil || s.db == nil {
		return progress, ErrStore
	}
	if s.secrets == nil {
		return progress, ErrMasterKey
	}
	if limit < 1 || limit > 25 {
		return progress, ErrUpdateSchedule
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM mdm_windows_update_schedules WHERE phase IN ('scheduled','waiting') AND LEAST(next_attempt_at,expires_at)<=clock_timestamp() ORDER BY LEAST(next_attempt_at,expires_at),id LIMIT $1`, limit)
	if err != nil {
		return progress, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
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
		phase, err := s.processUpdateSchedule(ctx, id)
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

func (s *Store) processUpdateSchedule(ctx context.Context, id string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	before, err := scanUpdateSchedule(tx.QueryRowContext(ctx, `SELECT `+updateScheduleColumns+` FROM mdm_windows_update_schedules WHERE id=$1`, id))
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if err := s.openUpdateSchedule(before); err != nil {
		return "", err
	}
	// Acquire the shared permission/scope locks before the schedule row lock,
	// matching cancellation and console operations. Authorization failure still
	// holds the shared permission lock while old authority is retired.
	authorizationErr := s.authorizeUpdateRing(ctx, tx, before.CreatedBy, before.Scope)
	if authorizationErr != nil && !errors.Is(authorizationErr, access.ErrDenied) && !errors.Is(authorizationErr, ErrNotFound) {
		return "", authorizationErr
	}
	r, err := scanUpdateSchedule(tx.QueryRowContext(ctx, `SELECT `+updateScheduleColumns+` FROM mdm_windows_update_schedules WHERE id=$1 AND phase IN ('scheduled','waiting') FOR UPDATE SKIP LOCKED`, id))
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if err := s.openUpdateSchedule(r); err != nil {
		return "", err
	}
	if updateSchedulePurpose(before) != updateSchedulePurpose(r) || !bytes.Equal(before.encryptedTargets, r.encryptedTargets) {
		return "", ErrAuthoritySecret
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return "", err
	}
	if now.Before(r.CreatedAt) || now.Before(r.UpdatedAt) {
		return "", ErrCSPDeadline
	}
	if now.Before(r.ExpiresAt) && (now.Before(r.NotBefore) || now.Before(r.NextAttemptAt)) {
		return "", nil
	}
	phase, reason := "", ""
	if !now.Before(r.ExpiresAt) {
		phase, reason = "expired", "activation_window_expired"
	} else if errors.Is(authorizationErr, access.ErrDenied) {
		phase, reason = "blocked", "authority_changed"
	} else if errors.Is(authorizationErr, ErrNotFound) {
		phase, reason = "blocked", "scope_changed"
	} else {
		var revision int64
		if err := tx.QueryRowContext(ctx, `SELECT revision FROM uem_access_revisions WHERE user_id=$1`, r.CreatedBy).Scan(&revision); err != nil {
			return "", err
		}
		if revision != r.CreatedByRevision {
			phase, reason = "blocked", "authority_changed"
		}
	}
	if phase != "" {
		if err := s.finishUpdateScheduleAttempt(ctx, tx, r, phase, reason, now); err != nil {
			return "", err
		}
		if err := tx.Commit(); err != nil {
			return "", err
		}
		return phase, nil
	}
	if _, err := tx.ExecContext(ctx, `SAVEPOINT windows_update_activation`); err != nil {
		return "", err
	}
	original := *r
	rollout, activationErr := s.activateUpdateSchedule(ctx, tx, r)
	if activationErr == nil {
		// Both audits may wait. Validate the complete activation window and the
		// earliest per-device expiry after those waits, immediately before commit.
		if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			activationErr = err
		} else if !now.Before(r.ExpiresAt) {
			activationErr = errUpdateActivationExpired
		} else if now.Before(r.NotBefore) || now.Before(r.UpdatedAt) {
			activationErr = ErrCSPDeadline
		} else {
			activationErr = checkUpdateRolloutDeadline(ctx, tx, rollout)
		}
	}
	if activationErr == nil {
		if err := tx.Commit(); err != nil {
			return "", err
		}
		return "activated", nil
	}
	if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT windows_update_activation`); err != nil {
		return "", err
	}
	*r = original
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return "", err
	}
	if now.Before(r.CreatedAt) || now.Before(r.UpdatedAt) {
		return "", ErrCSPDeadline
	}
	if !now.Before(r.ExpiresAt) || errors.Is(activationErr, errUpdateActivationExpired) {
		phase, reason = "expired", "activation_window_expired"
	} else {
		switch {
		case errors.Is(activationErr, ErrCSPQueueFull):
			phase, reason = "waiting", "device_queue_full"
		case errors.Is(activationErr, ErrCSPDeadline):
			phase, reason = "waiting", "admission_deadline_expired"
		case errors.Is(activationErr, errUpdateGroupSourcesChanged):
			phase, reason = "blocked", "group_sources_changed"
		case errors.Is(activationErr, ErrUpdateGroupConflict), errors.Is(activationErr, ErrUpdateGroup), errors.Is(activationErr, ErrUpdateGroupLarge):
			phase, reason = "blocked", "group_changed"
		case errors.Is(activationErr, ErrUpdateRingConflict):
			phase, reason = "blocked", "ring_assignment_conflict"
		case errors.Is(activationErr, access.ErrDenied):
			phase, reason = "blocked", "authority_changed"
		case errors.Is(activationErr, ErrNotFound), errors.Is(activationErr, ErrManagementIdentity):
			phase, reason = "blocked", "device_unavailable"
		default:
			return "", activationErr
		}
	}
	if err := s.finishUpdateScheduleAttempt(ctx, tx, r, phase, reason, now); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
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
	return s.writeUpdateSchedule(ctx, tx, r, "windows-update-scheduler")
}

func (s *Store) activateUpdateSchedule(ctx context.Context, tx *sql.Tx, r *updateStoredSchedule) (*UpdateRollout, error) {
	var group *updateGroupSelection
	if r.Group != nil {
		if r.groupSources != s.groupSources {
			return nil, errUpdateGroupSourcesChanged
		}
		group = &updateGroupSelection{ID: r.Group.ID, Revision: r.Group.Revision, Sources: s.groupSources}
	}

	rollout, err := s.assignUpdateRingTx(ctx, tx, r.CreatedBy, r.Scope, r.RingID, r.RingRevision, updateScheduleRolloutRequest(r.ID), r.Targets, r.Mode == "remove", r.Lifetime, r, group)
	if err != nil {
		return nil, err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	if !now.Before(r.ExpiresAt) {
		return nil, errUpdateActivationExpired
	}
	if now.Before(r.NotBefore) || now.Before(rollout.CreatedAt) {
		return nil, ErrCSPDeadline
	}
	r.RolloutID = rollout.ID
	if err := s.finishUpdateScheduleAttempt(ctx, tx, r, "activated", "", now); err != nil {
		return nil, err
	}
	return rollout, nil
}
