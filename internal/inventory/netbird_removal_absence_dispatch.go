package inventory

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

// A dispatch stop never claims cancellation, success, or safe native retry.
// An authorized operator can cancel the original request before native delivery
// and submit a new review. The original stop remains in history.
type NetbirdRemovalAbsenceDispatchStop struct {
	RequestID, Reason string
	RecordedAt        time.Time
}

func readAbsenceDispatchStop(ctx context.Context, tx *sql.Tx, id string) (*NetbirdRemovalAbsenceDispatchStop, error) {
	v := &NetbirdRemovalAbsenceDispatchStop{}
	err := tx.QueryRowContext(ctx, `SELECT request_id::text,reason,recorded_at FROM uem_netbird_removal_absence_dispatch_stops WHERE request_id=$1`, id).Scan(&v.RequestID, &v.Reason, &v.RecordedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (s *NetbirdRemovalAbsenceStore) ReadDispatchStop(parent context.Context, actor string, scope access.Scope, device, id, revision string) (*NetbirdRemovalAbsenceDispatchStop, error) {
	if parent == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, r, err := s.absenceRecord(ctx, actor, scope, device, id, revision, access.ReadSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	v, err := readAbsenceDispatchStop(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if err = removalAbsenceAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
		return nil, err
	}
	return v, tx.Commit()
}

func (s *NetbirdRemovalAbsenceStore) stopAbsenceDispatch(parent context.Context, r *NetbirdRemovalAbsence, reason string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
	defer cancel()
	tx, err := s.base.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var active bool
	err = tx.QueryRowContext(ctx, `SELECT cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL FROM uem_netbird_removal_absences WHERE id=$1 FOR UPDATE`, r.ID).Scan(&active)
	if err != nil {
		return err
	}
	var attempted, stopped bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_netbird_removal_absence_attempts WHERE request_id=$1),EXISTS(SELECT 1 FROM uem_netbird_removal_absence_dispatch_stops WHERE request_id=$1)`, r.ID).Scan(&attempted, &stopped); err != nil {
		return err
	}
	// Another worker may have delivered or an operator may have cancelled while
	// preflight failed. Neither case may be rewritten as a dispatch stop.
	if !active || attempted || stopped {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_removal_absence_dispatch_stops(request_id,reason) VALUES($1,$2)`, r.ID, reason); err != nil {
		return err
	}
	if err = removalAbsenceStageAudit(ctx, tx, r, r.Actor, "stopped", "dispatch-"+reason); err != nil {
		return err
	}
	return tx.Commit()
}

func absenceDispatchReason(err error) string {
	if errors.Is(err, access.ErrDenied) {
		return "not_authorized"
	}
	for _, known := range []error{ErrNotFound, ErrRefreshNotReady, ErrManualUnsupported, ErrNetbirdOperationChanged, ErrNetbirdOperationNotReady, ErrNetbirdOperationConflict} {
		if errors.Is(err, known) {
			return "source_changed"
		}
	}
	return ""
}

// DispatchOne selects work without reserving a database connection across RPCs.
// Verify commits its unique attempt before delivery, so concurrent dispatchers
// can race safely. A committed uncertain attempt is never selected for automatic
// redelivery, even after process restart.
func (s *NetbirdRemovalAbsenceStore) DispatchOne(parent context.Context) (bool, error) {
	if parent == nil || s == nil || s.execute == nil || s.base.control == nil {
		return false, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Minute)
	defer cancel()
	selectCtx, finish := context.WithTimeout(ctx, 10*time.Second)
	r, err := scanRemovalAbsence(s.base.db.QueryRowContext(selectCtx, `SELECT `+removalAbsenceColumns+` FROM uem_netbird_removal_absences i
 WHERE cancelled_at IS NULL AND completed_at IS NULL AND released_at IS NULL
 AND NOT EXISTS(SELECT 1 FROM uem_netbird_removal_absence_attempts WHERE request_id=i.id)
 AND NOT EXISTS(SELECT 1 FROM uem_netbird_removal_absence_dispatch_stops WHERE request_id=i.id)
 ORDER BY requested_at,id LIMIT 1`))
	finish()
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !time.Now().Before(r.ExpiresAt) {
		return true, s.stopAbsenceDispatch(ctx, r, "expired")
	}
	_, err = s.Verify(ctx, r.Actor, r.Scope, r.DeviceID, r.ID, r.Revision)
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	if err != nil {
		if reason := absenceDispatchReason(err); reason != "" {
			return true, s.stopAbsenceDispatch(ctx, r, reason)
		}
	}
	return true, err
}

// Run bounds parallel absence verifications and joins every callback on
// shutdown. The store's immutable admissions arbitrate other console instances.
func (s *NetbirdRemovalAbsenceStore) Run(ctx context.Context, logger *slog.Logger) {
	if ctx == nil || s == nil || s.execute == nil || s.base.control == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	var joined sync.WaitGroup
	for range 4 {
		joined.Add(1)
		go func() {
			defer joined.Done()
			tick := time.NewTicker(5 * time.Second)
			defer tick.Stop()
			for {
				for ctx.Err() == nil {
					worked, err := s.DispatchOne(ctx)
					if err != nil {
						if ctx.Err() == nil {
							logger.Warn("NetBird removal absence dispatch could not advance")
						}
						break
					}
					if !worked {
						break
					}
				}
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
				}
			}
		}()
	}
	joined.Wait()
}
