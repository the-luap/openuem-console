package apple

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type UpdateEscalationProgress struct{ Processed, Attention, Updated, Cleared, Blocked, Failed int }

// Monitoring is opt-in and produces console incidents only. Every watch is
// assessed under its recorded owner's current, unchanged grant revision.
func (s *Store) ProcessDueUpdateEscalations(ctx context.Context, permissions *access.Store, limit int) (UpdateEscalationProgress, error) {
	p := UpdateEscalationProgress{}
	if permissions == nil {
		return p, access.ErrDenied
	}
	if limit < 1 || limit > 25 {
		return p, ErrUpdateEscalation
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM mdm_apple_update_escalations WHERE phase='watching' AND next_check_at<=clock_timestamp() ORDER BY next_check_at,id LIMIT $1`, limit)
	if err != nil {
		return p, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return p, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return p, err
	}
	var first error
	for _, id := range ids {
		kind, err := s.processUpdateEscalation(ctx, permissions, id)
		if err != nil {
			p.Failed++
			if first == nil {
				first = err
			}
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if kind == "" {
			continue
		}
		p.Processed++
		switch kind {
		case "attention":
			p.Attention++
		case "updated":
			p.Updated++
		case "cleared":
			p.Cleared++
		case "blocked":
			p.Blocked++
		}
	}
	return p, first
}
func escalationDecisionsChanged(previous, current *UpdateEscalationSnapshot) bool {
	if previous == nil || current == nil {
		return previous != current
	}
	if len(previous.Devices) != len(current.Devices) {
		return true
	}
	for i, d := range current.Devices {
		if d.Decision != previous.Devices[i].Decision {
			return true
		}
	}
	return false
}
func applyUpdateEscalationReview(r *UpdateEscalation, review *UpdateGroupEscalationReview) (string, error) {
	open, awaiting, added, err := mergeUpdateEscalationTargets(r.OpenTargets, review.Decisions)
	if err != nil {
		return "", err
	}
	snapshot := escalationSnapshot(review)
	kind := ""
	switch {
	case added:
		kind = "attention"
		r.IncidentID = uuid.NewString()
		r.AcknowledgmentID = ""
	case len(open) == 0 && len(r.OpenTargets) > 0:
		kind = "cleared"
		r.IncidentID = ""
		r.AcknowledgmentID = ""
	case escalationDecisionsChanged(r.Snapshot, snapshot) || !slices.Equal(open, r.OpenTargets) || !slices.Equal(awaiting, r.AwaitingTargets):
		kind = "updated"
	}
	r.OpenTargets, r.AwaitingTargets = open, awaiting
	r.OpenCount, r.AwaitingCount = len(open), len(awaiting)
	r.Snapshot = snapshot
	r.CheckedAt = &snapshot.AssessedAt
	return kind, nil
}
func escalationSourceUnavailable(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, ErrUpdateEscalationIntegrity) || errors.Is(err, ErrUpdatePlanGroupIntegrity) || errors.Is(err, ErrUpdateExceptionIntegrity)
}
func (s *Store) processUpdateEscalation(ctx context.Context, permissions *access.Store, id string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	before, err := s.scanUpdateEscalation(tx.QueryRowContext(ctx, `SELECT `+updateEscalationColumns+` FROM mdm_apple_update_escalations WHERE id=$1`, id))
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	authorityErr := updateExceptionAuthority(ctx, tx, permissions, before.Actor, before.Scope)
	if authorityErr != nil && !errors.Is(authorityErr, access.ErrDenied) && !errors.Is(authorityErr, ErrNotFound) {
		return "", authorityErr
	}
	r, err := s.scanUpdateEscalation(tx.QueryRowContext(ctx, `SELECT `+updateEscalationColumns+` FROM mdm_apple_update_escalations WHERE id=$1 AND phase='watching' FOR UPDATE SKIP LOCKED`, id))
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	// A concurrent operator may have changed the owner/configuration before the
	// row lock. A future sweep must authorize that configuration independently.
	if updateEscalationConfigurationPurpose(before) != updateEscalationConfigurationPurpose(r) {
		return "", nil
	}
	now, err := updateEscalationClock(ctx, tx, r)
	if err != nil {
		return "", err
	}
	if r.NextCheckAt.After(now) {
		return "", nil
	}
	var actorRevision int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT revision FROM uem_access_revisions WHERE user_id=$1),0)`, r.Actor).Scan(&actorRevision); err != nil {
		return "", err
	}
	kind, reason := "", ""
	if authorityErr != nil || actorRevision != r.ActorRevision {
		kind, reason = "blocked", "authority_changed"
	} else {
		if _, err = tx.ExecContext(ctx, `SAVEPOINT apple_update_escalation_assessment`); err != nil {
			return "", err
		}
		sourceErr := s.validateUpdateEscalationSource(ctx, tx, r)
		if sourceErr == nil {
			sourceErr = s.validateUpdateEscalationReferences(ctx, tx, r)
		}
		var progress *UpdateGroupProgress
		if sourceErr == nil {
			progress, sourceErr = s.assessUpdateGroupProgressTransaction(ctx, tx, r.Scope, r.PlanID, r.AssignmentID)
		}
		if sourceErr != nil {
			if !escalationSourceUnavailable(sourceErr) {
				return "", sourceErr
			}
			if _, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT apple_update_escalation_assessment`); err != nil {
				return "", err
			}
			kind, reason = "blocked", "source_unavailable"
		} else {
			kind, err = applyUpdateEscalationReview(r, assessUpdateGroupEscalation(progress))
			if err != nil {
				return "", err
			}
		}
	}
	now, err = updateEscalationClock(ctx, tx, r)
	if err != nil {
		return "", err
	}
	previousRevision := r.StateRevision
	r.StateRevision++
	r.UpdatedAt = now
	next := now.Add(5 * time.Minute)
	r.NextCheckAt = &next
	if kind == "blocked" {
		r.Phase = "blocked"
		r.Reason = reason
		r.NextCheckAt = nil
	}
	if err = s.persistUpdateEscalation(ctx, tx, r, previousRevision); err != nil {
		return "", err
	}
	if kind != "" {
		if err = s.insertUpdateEscalationEvent(ctx, tx, escalationEvent(r, kind, r.Actor, r.ActorRevision)); err != nil {
			return "", err
		}
	}
	if err = auditUpdateEscalation(ctx, tx, r.Scope, r.Actor, "checked", r.ID, r.StateRevision); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	if kind == "" {
		kind = "checked"
	}
	return kind, nil
}
func (s *Store) RunUpdateEscalations(ctx context.Context, permissions *access.Store, logger *slog.Logger) {
	runUpdateEscalations(ctx, logger, time.Minute, 30*time.Second, func(ctx context.Context, limit int) (UpdateEscalationProgress, error) {
		return s.ProcessDueUpdateEscalations(ctx, permissions, limit)
	})
}
func runUpdateEscalations(ctx context.Context, logger *slog.Logger, interval, timeout time.Duration, process func(context.Context, int) (UpdateEscalationProgress, error)) {
	if logger == nil {
		logger = slog.Default()
	}
	for ctx.Err() == nil {
		pass, cancel := context.WithTimeout(ctx, timeout)
		_, err := process(pass, 25)
		cancel()
		if err != nil && ctx.Err() == nil {
			logger.Error("Apple update escalation processing failed")
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
