package apple

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type WindowsSoftwareReconciliationReview struct {
	Request                WindowsSoftwareRequest
	Version                *SoftwareVersion
	Original               *registry.SoftwareTaskStatus
	TargetName, ReviewHash string
	ExpiresAt              time.Time
	Expectation            enrollment.SoftwareExpectation
}

type WindowsSoftwareReconciliationsPage struct {
	Request   WindowsSoftwareRequest
	Version   *SoftwareVersion
	Original  *registry.SoftwareTaskStatus
	Checks    []registry.SoftwareReconciliationStatus
	Next      string
	HasActive bool
}

func windowsReconciliationRequest(ctx context.Context, tx *sql.Tx, scope Scope, version, id, actor string, permissions *access.Store, mutation bool) (*WindowsSoftwareRequest, string, error) {
	if err := windowsSoftwarePermissions(ctx, tx, permissions, actor, scope, mutation); err != nil {
		return nil, "", err
	}
	r, err := scanWindowsSoftwareRequest(tx.QueryRowContext(ctx, `SELECT `+windowsRequestColumns+` FROM uem_windows_software_requests r WHERE r.id=$1 AND r.version_id=$2 AND r.tenant_id=$3 AND ($4::bigint=0 OR r.site_id=$4)`, id, version, scope.TenantID, scope.SiteID))
	if err != nil {
		return nil, "", err
	}
	if err = windowsSoftwarePermissions(ctx, tx, permissions, actor, Scope{TenantID: r.TenantID, SiteID: r.SiteID}, mutation); err != nil {
		return nil, "", err
	}
	if r.Status != "dispatched" {
		return nil, "", ErrConflict
	}
	var original string
	err = tx.QueryRowContext(ctx, `SELECT id FROM uem_windows_software_dispatches WHERE preparation_id=$1 AND version_id=$2 AND agent_id=$3 AND tenant_id=$4 AND site_id=$5`, r.ID, r.VersionID, r.AgentID, r.TenantID, r.SiteID).Scan(&original)
	return r, original, notFound(err)
}

func windowsReconciliationOriginal(ctx context.Context, tx *sql.Tx, channel *registry.AccessStore, r WindowsSoftwareRequest, original string) (*registry.SoftwareTaskStatus, error) {
	status, err := channel.ReadSoftwareTaskInTransaction(ctx, tx, registry.Scope{TenantID: r.TenantID, SiteID: r.SiteID}, original)
	if err != nil {
		return nil, err
	}
	if status.PreparationID != r.ID || status.RevisionID != r.VersionID || status.AgentID != r.AgentID || status.Operation != r.Operation {
		return nil, ErrConflict
	}
	return status, nil
}

// Identity precedes inventory/site and original-task locks, matching the worker.
// A withdrawn catalog revision remains observable: this authorizes no execution.
func (s *Store) windowsReconciliationReview(ctx context.Context, tx *sql.Tx, scope Scope, version, id, actor string, expires time.Time, permissions *access.Store) (*WindowsSoftwareReconciliationReview, error) {
	r, originalID, err := windowsReconciliationRequest(ctx, tx, scope, version, id, actor, permissions, true)
	if err != nil {
		return nil, err
	}
	bound := Scope{TenantID: r.TenantID, SiteID: r.SiteID}
	channel, _ := registry.NewAccessStore(s.db)
	identity, certificate, _, err := channel.SoftwareIdentity(ctx, tx, registry.Scope{TenantID: r.TenantID, SiteID: r.SiteID}, r.AgentID)
	if err != nil {
		return nil, ErrConflict
	}
	var name string
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(NULLIF(a.nickname,''),a.hostname) FROM agents a JOIN uem_agent_identities i ON a.oid=i.id::text WHERE a.oid=$1 AND lower(a.os)='windows' AND a.agent_status IN ('Enabled','No contact') AND i.architecture IN ('amd64','arm64') FOR UPDATE OF a`, r.AgentID).Scan(&name)
	if err != nil {
		return nil, ErrConflict
	}
	rows, err := tx.QueryContext(ctx, `SELECT site_id FROM site_agents WHERE agent_id=$1 ORDER BY site_id LIMIT 2 FOR SHARE`, r.AgentID)
	if err != nil {
		return nil, err
	}
	count := 0
	for rows.Next() {
		var site int
		if rows.Scan(&site) != nil || site != r.SiteID {
			rows.Close()
			return nil, ErrConflict
		}
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, ErrConflict
	}
	original, err := windowsReconciliationOriginal(ctx, tx, channel, *r, originalID)
	if err != nil {
		return nil, err
	}
	if original.DeliveredAt == nil || original.ReconciliationID != "" || original.Status != "uncertain" && original.Status != "restart_required" {
		return nil, ErrConflict
	}
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_software_reconciliations WHERE original_task_id=$1 AND status IN ('pending','delivered') AND expires_at>clock_timestamp())`, originalID).Scan(&active); err != nil {
		return nil, err
	}
	if active {
		return nil, ErrConflict
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	if expires.IsZero() {
		expires = now.Add(15 * time.Minute).Truncate(time.Second)
		if certificate.NotAfter.Before(expires) {
			expires = certificate.NotAfter.Truncate(time.Second)
		}
	}
	if !expires.Equal(expires.Truncate(time.Second)) || !expires.After(now.Add(time.Minute)) || expires.After(now.Add(time.Hour)) || expires.After(certificate.NotAfter) {
		return nil, ErrConflict
	}
	v, err := softwareVersionTx(ctx, tx, bound, version)
	if err != nil {
		return nil, err
	}
	if v.Platform != "windows" {
		return nil, ErrConflict
	}
	var hash string
	var contextWire []byte
	if err = tx.QueryRowContext(ctx, `SELECT task_hash,task_context FROM uem_agent_software_tasks WHERE id=$1 AND tenant_id=$2 AND site_id=$3`, originalID, r.TenantID, r.SiteID).Scan(&hash, &contextWire); err != nil {
		return nil, err
	}
	var originalContext enrollment.SoftwareContext
	if json.Unmarshal(contextWire, &originalContext) != nil || !originalContext.ValidShape() || originalContext.TaskID != originalID {
		return nil, ErrConflict
	}
	data, err := json.Marshal(struct {
		Request, Revision, Device, OriginalHash, Certificate, Actor string
		Tenant, Site                                                int
		Expires                                                     int64
		Original                                                    *registry.SoftwareTaskStatus
	}{r.ID, version, r.AgentID, hash, identity.CertificateHash, actor, r.TenantID, r.SiteID, expires.Unix(), original})
	if err != nil {
		return nil, ErrWindowsSoftware
	}
	sum := sha256.Sum256(data)
	return &WindowsSoftwareReconciliationReview{Request: *r, Version: v, Original: original, TargetName: name, ReviewHash: hex.EncodeToString(sum[:]), ExpiresAt: expires.UTC(), Expectation: originalContext.Expectation}, nil
}

func (s *Store) ReviewWindowsSoftwareReconciliation(ctx context.Context, scope Scope, version, id, actor string, permissions *access.Store) (*WindowsSoftwareReconciliationReview, error) {
	if scope.Validate() != nil || actor == "" || permissions == nil {
		return nil, access.ErrDenied
	}
	if !enrollment.ValidDeviceID(version) || !enrollment.ValidDeviceID(id) {
		return nil, ErrWindowsSoftware
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	review, err := s.windowsReconciliationReview(ctx, tx, scope, version, id, actor, time.Time{}, permissions)
	if err != nil {
		return nil, err
	}
	if err = windowsRequestAudit(ctx, tx, Scope{TenantID: review.Request.TenantID, SiteID: review.Request.SiteID}, actor, "software.windows.reconciliation.review", id); err != nil {
		return nil, err
	}
	return review, tx.Commit()
}

func (s *Store) QueueWindowsSoftwareReconciliation(ctx context.Context, scope Scope, version, id, reconciliationID, reviewHash, actor string, expires time.Time, permissions *access.Store) (*registry.SoftwareReconciliationStatus, error) {
	if scope.Validate() != nil || actor == "" || permissions == nil {
		return nil, access.ErrDenied
	}
	if !enrollment.ValidDeviceID(version) || !enrollment.ValidDeviceID(id) || !enrollment.ValidDeviceID(reconciliationID) || !validWindowsDigest(reviewHash) || expires.IsZero() || !expires.Equal(expires.Truncate(time.Second)) {
		return nil, ErrWindowsSoftware
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, originalID, err := windowsReconciliationRequest(ctx, tx, scope, version, id, actor, permissions, true)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "windows-software-reconciliation:"+strconv.Itoa(scope.TenantID)+":"+reconciliationID); err != nil {
		return nil, err
	}
	channel, _ := registry.NewAccessStore(s.db)
	bound := registry.Scope{TenantID: r.TenantID, SiteID: r.SiteID}
	var priorRequest, priorVersion, priorActor, priorHash, priorOriginal, priorDevice string
	var priorSite int
	var priorExpires time.Time
	err = tx.QueryRowContext(ctx, `SELECT preparation_id,version_id,actor,review_hash,site_id,expires_at,original_task_id,agent_id FROM uem_windows_software_reconciliations WHERE id=$1 AND tenant_id=$2`, reconciliationID, scope.TenantID).Scan(&priorRequest, &priorVersion, &priorActor, &priorHash, &priorSite, &priorExpires, &priorOriginal, &priorDevice)
	if err == nil {
		if priorRequest != id || priorVersion != version || priorActor != actor || priorHash != reviewHash || priorSite != r.SiteID || !priorExpires.Equal(expires) || priorOriginal != originalID || priorDevice != r.AgentID {
			return nil, ErrConflict
		}
		status, err := channel.ReadSoftwareReconciliationInTransaction(ctx, tx, bound, reconciliationID)
		if err != nil {
			return nil, err
		}
		return status, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	review, err := s.windowsReconciliationReview(ctx, tx, scope, version, id, actor, expires, permissions)
	if err != nil {
		return nil, err
	}
	if review.ReviewHash != reviewHash {
		return nil, ErrConflict
	}
	if _, err = s.agentRegistry.QueueSoftwareReconciliationInTransaction(ctx, tx, bound, r.AgentID, originalID, reconciliationID, expires, actor); err != nil {
		return nil, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_windows_software_reconciliations(id,tenant_id,site_id,agent_id,version_id,preparation_id,original_task_id,actor,review_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, reconciliationID, r.TenantID, r.SiteID, r.AgentID, version, id, originalID, actor, reviewHash, expires); err != nil {
		return nil, err
	}
	if err = windowsRequestAudit(ctx, tx, Scope{TenantID: r.TenantID, SiteID: r.SiteID}, actor, "software.windows.reconciliation.queue", reconciliationID); err != nil {
		return nil, err
	}
	var current bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_software_reconciliations r JOIN uem_agent_identities i ON i.id=r.device_id AND i.tenant_id=r.tenant_id AND i.site_id=r.site_id AND i.certificate_hash=r.certificate_hash WHERE r.id=$1 AND i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp() AND r.expires_at>clock_timestamp())`, reconciliationID).Scan(&current); err != nil || !current {
		return nil, ErrConflict
	}
	status, err := channel.ReadSoftwareReconciliationInTransaction(ctx, tx, bound, reconciliationID)
	if err != nil {
		return nil, err
	}
	return status, tx.Commit()
}

func (s *Store) ReadWindowsSoftwareReconciliations(ctx context.Context, scope Scope, version, id, before, actor string, permissions *access.Store) (*WindowsSoftwareReconciliationsPage, error) {
	if scope.Validate() != nil || actor == "" || permissions == nil {
		return nil, access.ErrDenied
	}
	if !enrollment.ValidDeviceID(version) || !enrollment.ValidDeviceID(id) || before != "" && !enrollment.ValidDeviceID(before) {
		return nil, ErrWindowsSoftware
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, originalID, err := windowsReconciliationRequest(ctx, tx, scope, version, id, actor, permissions, false)
	if err != nil {
		return nil, err
	}
	bound := Scope{TenantID: r.TenantID, SiteID: r.SiteID}
	channel, _ := registry.NewAccessStore(s.db)
	original, err := windowsReconciliationOriginal(ctx, tx, channel, *r, originalID)
	if err != nil {
		return nil, err
	}
	v, err := softwareVersionTx(ctx, tx, bound, version)
	if err != nil {
		return nil, err
	}
	page := &WindowsSoftwareReconciliationsPage{Request: *r, Version: v, Original: original}
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_software_reconciliations WHERE original_task_id=$1 AND status IN ('pending','delivered') AND expires_at>clock_timestamp())`, originalID).Scan(&page.HasActive); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM uem_agent_software_reconciliations WHERE tenant_id=$1 AND site_id=$2 AND device_id=$3 AND original_task_id=$4 AND ($5='' OR (created_at,id)<(SELECT created_at,id FROM uem_agent_software_reconciliations WHERE id=NULLIF($5,'')::uuid AND tenant_id=$1 AND site_id=$2 AND device_id=$3 AND original_task_id=$4)) ORDER BY created_at DESC,id DESC LIMIT 51`, r.TenantID, r.SiteID, r.AgentID, originalID, before)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, value)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(ids) > 50 {
		page.Next, ids = ids[49], ids[:50]
	}
	for _, value := range ids {
		status, err := channel.ReadSoftwareReconciliationInTransaction(ctx, tx, registry.Scope{TenantID: r.TenantID, SiteID: r.SiteID}, value)
		if err != nil {
			return nil, err
		}
		if status.OriginalTaskID != originalID || status.AgentID != r.AgentID {
			return nil, ErrConflict
		}
		page.Checks = append(page.Checks, *status)
	}
	if err = windowsRequestAudit(ctx, tx, bound, actor, "software.windows.reconciliation.read", originalID); err != nil {
		return nil, err
	}
	return page, tx.Commit()
}

func (s *Store) CancelWindowsSoftwareReconciliation(ctx context.Context, scope Scope, version, id, reconciliationID, actor string, permissions *access.Store) error {
	if scope.Validate() != nil || actor == "" || permissions == nil {
		return access.ErrDenied
	}
	if !enrollment.ValidDeviceID(version) || !enrollment.ValidDeviceID(id) || !enrollment.ValidDeviceID(reconciliationID) {
		return ErrWindowsSoftware
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, originalID, err := windowsReconciliationRequest(ctx, tx, scope, version, id, actor, permissions, true)
	if err != nil {
		return err
	}
	var matches bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_software_reconciliations WHERE id=$1 AND original_task_id=$2 AND tenant_id=$3 AND site_id=$4 AND device_id=$5)`, reconciliationID, originalID, r.TenantID, r.SiteID, r.AgentID).Scan(&matches); err != nil {
		return err
	}
	if !matches {
		return ErrNotFound
	}
	channel, _ := registry.NewAccessStore(s.db)
	if _, err = channel.CancelSoftwareReconciliationInTransaction(ctx, tx, registry.Scope{TenantID: r.TenantID, SiteID: r.SiteID}, reconciliationID, actor); err != nil {
		return ErrConflict
	}
	return tx.Commit()
}
