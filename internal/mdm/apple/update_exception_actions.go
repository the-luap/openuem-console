package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type UpdateExceptionReview struct {
	Scope                 Scope            `json:"-" xml:"-" yaml:"-"`
	DeviceID              string           `json:"-" xml:"-" yaml:"-"`
	ScopeRevision         int64            `json:"-" xml:"-" yaml:"-"`
	Name                  string           `json:"-" xml:"-" yaml:"-"`
	Availability          string           `json:"-" xml:"-" yaml:"-"`
	Policy                *UpdatePolicy    `json:"-" xml:"-" yaml:"-"`
	Current               *UpdateException `json:"-" xml:"-" yaml:"-"`
	NotificationAvailable bool             `json:"-" xml:"-" yaml:"-"`
	ReviewToken           string           `json:"-" xml:"-" yaml:"-"`
	AssessedAt            time.Time        `json:"-" xml:"-" yaml:"-"`
	device                *Device
	previous              *UpdateException
}

func (UpdateExceptionReview) String() string     { return "[protected Apple update exception review]" }
func (v UpdateExceptionReview) GoString() string { return v.String() }

type UpdateExceptionRequest struct {
	DeviceID    string     `json:"-" xml:"-" yaml:"-"`
	RequestKey  string     `json:"-" xml:"-" yaml:"-"`
	Kind        string     `json:"-" xml:"-" yaml:"-"`
	Reason      string     `json:"-" xml:"-" yaml:"-"`
	ExpiresAt   *time.Time `json:"-" xml:"-" yaml:"-"`
	ReviewToken string     `json:"-" xml:"-" yaml:"-"`
}

func (UpdateExceptionRequest) String() string     { return "[protected Apple update exception request]" }
func (v UpdateExceptionRequest) GoString() string { return v.String() }

func updateExceptionAuthority(ctx context.Context, tx *sql.Tx, permissions *access.Store, actor string, scope Scope) error {
	if err := updatePlanAuthority(ctx, tx, permissions, actor, scope, access.ManageUpdates); err != nil {
		return err
	}
	return permissions.AuthorizeTransaction(ctx, tx, actor, access.ReadDevices, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID})
}

func auditUpdateException(ctx context.Context, tx *sql.Tx, scope Scope, actor, action, id string, revision int) error {
	details, err := json.Marshal(map[string]any{"site_id": scope.SiteID, "revision": revision, "result": "success"})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,details) VALUES($1,$2,$3,$4,$5)`, scope.TenantID, actor, "apple.update.exception."+action, id, details)
	return err
}

func (s *Store) inspectUpdateException(ctx context.Context, tx *sql.Tx, scope Scope, id string, admitting bool) (*UpdateExceptionReview, error) {
	lock := " FOR SHARE"
	if admitting {
		lock = " FOR UPDATE"
	}
	d := &Device{ID: id, TenantID: scope.TenantID, SiteID: scope.SiteID}
	var enrolled bool
	var scopeRevision int64
	err := tx.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(name)<=512 THEN name ELSE '' END,status='enrolled',certificate_expires_at,CASE WHEN octet_length(model)<=255 THEN model ELSE '' END,CASE WHEN octet_length(os_version)<=32 THEN os_version ELSE '' END,CASE WHEN octet_length(platform)<=32 THEN platform ELSE 'unknown' END,supervised,supervised_reported,update_exception_scope_revision FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND site_id=$3`+lock, id, scope.TenantID, scope.SiteID).Scan(&d.Name, &enrolled, &d.CertificateExpiresAt, &d.Model, &d.OSVersion, &d.OSFamily, &d.Supervised, &d.SupervisedReported, &scopeRevision)
	if err != nil {
		return nil, notFound(err)
	}
	p := &UpdateExceptionReview{Scope: scope, ScopeRevision: scopeRevision, DeviceID: id, Name: d.Name, Availability: "not_managed", device: d}
	if enrolled {
		d.Status, p.Availability = "enrolled", "available"
	}
	p.NotificationAvailable = d.Capabilities().DeclarativeManagement
	if p.Policy, err = currentUpdateGroupPolicy(ctx, tx, id); err != nil {
		return nil, err
	}
	if p.previous, err = s.lastUpdateException(ctx, tx, scope, id); err != nil {
		return nil, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&p.AssessedAt); err != nil {
		return nil, err
	}
	if p.Availability == "available" && !d.CertificateExpiresAt.After(p.AssessedAt) {
		p.Availability = "identity_expired"
	}
	previous, revision := "", 0
	if p.previous != nil {
		if p.previous.CreatedAt.After(p.AssessedAt) {
			return nil, ErrUpdateExceptionIntegrity
		}
		previous, revision = p.previous.ID, p.previous.Revision
		if p.previous.ScopeRevision == scopeRevision {
			p.Current = p.previous
		}
	}
	p.ReviewToken = updateExceptionReviewToken(scope, id, p.Policy, previous, revision, p.NotificationAvailable, scopeRevision)
	return p, nil
}

func (s *Store) ReviewUpdateException(ctx context.Context, actor string, permissions *access.Store, scope Scope, id string) (*UpdateExceptionReview, error) {
	if !profileRevisionUUID(id) {
		return nil, ErrUpdateException
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = updateExceptionAuthority(ctx, tx, permissions, actor, scope); err != nil {
		return nil, err
	}
	p, err := s.inspectUpdateException(ctx, tx, scope, id, false)
	if err != nil {
		return nil, err
	}
	if err = auditUpdateException(ctx, tx, scope, actor, "review", id, 0); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}

// A pause removes the reviewed configured policy and prevents subsequent policy
// admission until expiry or a reviewed resume. Resume never restores old policy.
func (s *Store) RecordUpdateException(ctx context.Context, actor string, permissions *access.Store, scope Scope, request UpdateExceptionRequest) (*UpdateException, error) {
	if !profileRevisionUUID(request.DeviceID) || !profileRevisionUUID(request.RequestKey) || !validUpdateExceptionReason(request.Reason) || !updateGroupPolicyToken.MatchString(request.ReviewToken) || (request.Kind != "pause" && request.Kind != "resume") || (request.Kind == "pause" && (request.ExpiresAt == nil || request.ExpiresAt.Nanosecond() != 0)) || (request.Kind == "resume" && request.ExpiresAt != nil) {
		return nil, ErrUpdateException
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = updateExceptionAuthority(ctx, tx, permissions, actor, scope); err != nil {
		return nil, err
	}
	var actorRevision int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT revision FROM uem_access_revisions WHERE user_id=$1),0)`, actor).Scan(&actorRevision); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629909,hashtext($1))`, fmt.Sprintf("%d/%d/%s", scope.TenantID, scope.SiteID, request.RequestKey)); err != nil {
		return nil, err
	}
	previous, err := s.scanUpdateException(tx.QueryRowContext(ctx, `SELECT `+updateExceptionColumns+` FROM mdm_apple_update_exceptions WHERE tenant_id=$1 AND site_id=$2 AND request_key=$3`, scope.TenantID, scope.SiteID, request.RequestKey))
	if err == nil {
		sameExpiry := (previous.ExpiresAt == nil && request.ExpiresAt == nil) || (previous.ExpiresAt != nil && request.ExpiresAt != nil && previous.ExpiresAt.Equal(*request.ExpiresAt))
		if previous.Actor != actor || previous.ActorRevision != actorRevision || previous.DeviceID != request.DeviceID || previous.Kind != request.Kind || previous.Reason != request.Reason || previous.ReviewToken != request.ReviewToken || !sameExpiry {
			return nil, ErrConflict
		}
		if err = auditUpdateException(ctx, tx, scope, actor, "replayed", previous.ID, previous.Revision); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return previous, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	p, err := s.inspectUpdateException(ctx, tx, scope, request.DeviceID, true)
	if err != nil {
		return nil, err
	}
	if p.Availability != "available" {
		return nil, ErrConflict
	}
	if p.ReviewToken != request.ReviewToken {
		return nil, ErrUpdateExceptionReview
	}
	if request.Kind == "resume" && !p.Current.Active(p.AssessedAt) {
		return nil, ErrConflict
	}
	if request.Kind == "pause" && (!request.ExpiresAt.After(p.AssessedAt) || request.ExpiresAt.After(p.AssessedAt.Add(30*24*time.Hour))) {
		return nil, ErrUpdateException
	}
	r := &UpdateException{ID: uuid.NewString(), Scope: scope, ScopeRevision: p.ScopeRevision, DeviceID: request.DeviceID, Revision: 1, RequestKey: request.RequestKey, Actor: actor, ActorRevision: actorRevision, Kind: request.Kind, ExpiresAt: request.ExpiresAt, Reason: request.Reason, ReviewToken: request.ReviewToken, PreviousPolicy: p.Policy, NotificationAvailable: p.NotificationAvailable}
	if p.previous != nil {
		r.PreviousID, r.Revision = p.previous.ID, p.previous.Revision+1
	}
	if r.Revision > 2147483647 {
		return nil, ErrUpdateExceptionIntegrity
	}
	if request.Kind == "pause" {
		if err = s.setDeviceUpdatePolicy(ctx, tx, p.device, nil); err != nil {
			return nil, err
		}
		if r.NotificationAvailable {
			if err = tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_commands WHERE tenant_id=$1 AND device_id=$2 AND request_type='DeclarativeManagement' AND status='queued'`, scope.TenantID, r.DeviceID).Scan(&r.CommandID); err != nil {
				return nil, err
			}
		}
		if err = audit(ctx, tx, scope.TenantID, actor, "apple.update.policy", r.DeviceID); err != nil {
			return nil, err
		}
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&r.CreatedAt); err != nil {
		return nil, err
	}
	if p.previous != nil && r.CreatedAt.Before(p.previous.CreatedAt) {
		return nil, ErrUpdateExceptionIntegrity
	}
	if r.Kind == "pause" && !r.ExpiresAt.After(r.CreatedAt) {
		return nil, ErrConflict
	}
	encrypted, err := s.sealUpdateException(r)
	if err != nil {
		return nil, err
	}
	var parent any
	if r.PreviousID != "" {
		parent = r.PreviousID
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_update_exceptions(id,tenant_id,site_id,device_id,revision,previous_id,request_key,actor,actor_revision,kind,created_at,expires_at,encrypted_intent,scope_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, r.ID, scope.TenantID, scope.SiteID, r.DeviceID, r.Revision, parent, r.RequestKey, r.Actor, r.ActorRevision, r.Kind, r.CreatedAt, r.ExpiresAt, encrypted, r.ScopeRevision); err != nil {
		return nil, err
	}
	if err = auditUpdateException(ctx, tx, scope, actor, "recorded", r.ID, r.Revision); err != nil {
		return nil, err
	}
	var completed time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&completed); err != nil {
		return nil, err
	}
	if !p.device.CertificateExpiresAt.After(completed) || (r.Kind == "pause" && !r.ExpiresAt.After(completed)) {
		return nil, ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}
