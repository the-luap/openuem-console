package inventory

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

// Absence status is a coherent snapshot of retained evidence. It never
// consults a device or depends on present native state or enrollment ownership.
type NetbirdRemovalAbsenceStatus struct {
	Request      *NetbirdRemovalAbsence
	Delivery     *NetbirdRemovalAbsenceDelivery
	DispatchStop *NetbirdRemovalAbsenceDispatchStop
	Resolution   *NetbirdRemovalAbsenceResolution
}

func (s NetbirdRemovalAbsenceStatus) State() string {
	switch {
	case s.Request.CancelledAt != nil:
		return "cancelled"
	case s.Request.CompletedAt != nil:
		return "completed"
	case s.Request.ReleasedAt != nil:
		return "released"
	case s.Delivery != nil:
		if s.Delivery.Outcome == "pending" {
			return "delivery_pending"
		}
		return s.Delivery.Outcome
	case s.DispatchStop != nil:
		return "stopped"
	default:
		return "queued"
	}
}

func readAbsenceStatus(ctx context.Context, tx *sql.Tx, scope access.Scope, device, id string) (*NetbirdRemovalAbsenceStatus, error) {
	r, err := scanRemovalAbsence(tx.QueryRowContext(ctx, `SELECT `+removalAbsenceColumns+` FROM uem_netbird_removal_absences WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR SHARE`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out := &NetbirdRemovalAbsenceStatus{Request: r}
	out.Delivery, err = readRemovalAbsenceDelivery(ctx, tx, id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	out.DispatchStop, err = readAbsenceDispatchStop(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	out.Resolution, err = readAbsenceResolution(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *NetbirdRemovalAbsenceStore) Status(parent context.Context, actor string, scope access.Scope, device, id string) (*NetbirdRemovalAbsenceStatus, error) {
	if parent == nil || !canonicalRequestID(device) || !canonicalRequestID(id) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.base.begin(ctx, actor, scope, access.ReadSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out, err := readAbsenceStatus(ctx, tx, scope, device, id)
	if err != nil {
		return nil, err
	}
	if err = removalAbsenceAudit(ctx, tx, actor, out.Request, "read", "recorded"); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

type NetbirdRemovalAbsenceHistory struct {
	Requests []*NetbirdRemovalAbsenceStatus
	Next     string
}

func (s *NetbirdRemovalAbsenceStore) History(parent context.Context, actor string, scope access.Scope, device, before string) (*NetbirdRemovalAbsenceHistory, error) {
	if parent == nil || !canonicalRequestID(device) || before != "" && !canonicalRequestID(before) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.base.begin(ctx, actor, scope, access.ReadSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var at time.Time
	if before != "" {
		err = tx.QueryRowContext(ctx, `SELECT requested_at FROM uem_netbird_removal_absences WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4`, before, device, scope.TenantID, scope.SiteID).Scan(&at)
		if errors.Is(err, sql.ErrNoRows) {
			err = ErrNotFound
		}
		if err != nil {
			return nil, err
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT id::text FROM uem_netbird_removal_absences WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND ($4='' OR (requested_at,id)<($5,nullif($4,'')::uuid)) ORDER BY requested_at DESC,id DESC LIMIT 21`, device, scope.TenantID, scope.SiteID, before, at)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out := &NetbirdRemovalAbsenceHistory{Requests: []*NetbirdRemovalAbsenceStatus{}}
	if len(ids) > 20 {
		ids = ids[:20]
		out.Next = ids[19]
	}
	for _, id := range ids {
		v, err := readAbsenceStatus(ctx, tx, scope, device, id)
		if err != nil {
			return nil, err
		}
		out.Requests = append(out.Requests, v)
	}
	if err = removalAbsenceAudit(ctx, tx, actor, &NetbirdRemovalAbsence{DeviceID: device, Scope: scope}, "read", "recorded"); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}
