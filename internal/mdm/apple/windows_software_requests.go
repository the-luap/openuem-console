package apple

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// A preparation records operator intent only. It carries no execution payload,
// broker command or observed state, and expires without becoming deliverable.
type WindowsSoftwareRequest struct {
	ID, AgentID, VersionID, Operation, Actor, Status string
	TenantID, SiteID                                 int
	CreatedAt, ExpiresAt                             time.Time
	CompletedAt                                      *time.Time
}

type WindowsSoftwareTarget struct {
	ID, Name, Architecture string
	SiteID                 int
}
type WindowsSoftwareRequestsPage struct {
	Version                 *SoftwareVersion
	Targets                 []WindowsSoftwareTarget
	Requests                []WindowsSoftwareRequest
	NextTarget, NextRequest string
}

const windowsRequestColumns = `r.id,r.tenant_id,r.site_id,r.agent_id,r.version_id,r.operation,r.actor,
 CASE WHEN r.status='prepared' AND r.expires_at<=clock_timestamp() THEN 'expired' ELSE r.status END,
 r.created_at,r.expires_at,r.completed_at`

func scanWindowsSoftwareRequest(row interface{ Scan(...any) error }) (*WindowsSoftwareRequest, error) {
	r := new(WindowsSoftwareRequest)
	err := row.Scan(&r.ID, &r.TenantID, &r.SiteID, &r.AgentID, &r.VersionID, &r.Operation, &r.Actor, &r.Status, &r.CreatedAt, &r.ExpiresAt, &r.CompletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func windowsSoftwarePermissions(ctx context.Context, tx *sql.Tx, permissions *access.Store, actor string, scope Scope, mutation bool) error {
	if permissions == nil || actor == "" || scope.Validate() != nil {
		return access.ErrDenied
	}
	actions := []access.Capability{access.ReadSoftware, access.ReadDevices}
	if mutation {
		actions = append(actions, access.AssignSoftware)
	}
	for _, action := range actions {
		if err := permissions.AuthorizeTransaction(ctx, tx, actor, action, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}); err != nil {
			return err
		}
	}
	return nil
}

func windowsRequestAudit(ctx context.Context, tx *sql.Tx, scope Scope, actor, action, id string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,details) VALUES($1,$2,$3,$4,jsonb_build_object('site_id',$5::bigint,'result','success'))`, scope.TenantID, actor, action, id, scope.SiteID)
	return err
}

// PrepareWindowsSoftware binds an immutable revision to the current individual
// identity and the sole inventory site. The identity lock precedes inventory
// locks, matching worker authorization. The per-device reservation intentionally
// covers every package to avoid aliasing the same MSI product/registry key.
func (s *Store) PrepareWindowsSoftware(ctx context.Context, scope Scope, requestID, version, device, operation, actor string, permissions *access.Store) (*WindowsSoftwareRequest, error) {
	if scope.Validate() != nil || permissions == nil || actor == "" {
		return nil, access.ErrDenied
	}
	if !enrollment.ValidDeviceID(requestID) || !enrollment.ValidDeviceID(version) || !enrollment.ValidDeviceID(device) || (operation != "install" && operation != "remove") {
		return nil, ErrWindowsSoftware
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = windowsSoftwarePermissions(ctx, tx, permissions, actor, scope, true); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "windows-software-request:"+strconv.Itoa(scope.TenantID)+":"+requestID); err != nil {
		return nil, err
	}
	// Replays never extend lifetime, resurrect cancellation, or acquire another
	// identity generation. They still require current rights in the original site.
	prior, err := scanWindowsSoftwareRequest(tx.QueryRowContext(ctx, `SELECT `+windowsRequestColumns+` FROM uem_windows_software_requests r WHERE r.tenant_id=$1 AND r.request_id=$2`, scope.TenantID, requestID))
	if err == nil {
		if (scope.SiteID != 0 && scope.SiteID != prior.SiteID) || prior.Actor != actor || prior.VersionID != version || prior.AgentID != device || prior.Operation != operation {
			return nil, ErrConflict
		}
		if err = windowsSoftwarePermissions(ctx, tx, permissions, actor, Scope{TenantID: prior.TenantID, SiteID: prior.SiteID}, true); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return prior, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	var site int
	var certificate, architecture string
	var expiry time.Time
	err = tx.QueryRowContext(ctx, `SELECT i.site_id,i.certificate_hash,i.architecture,i.certificate_expires_at FROM uem_agent_identities i JOIN sites s ON s.id=i.site_id AND s.tenant_sites=i.tenant_id WHERE i.id=$1 AND i.tenant_id=$2 AND ($3::bigint=0 OR i.site_id=$3) AND i.platform='windows' AND i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp() FOR UPDATE OF i FOR SHARE OF s`, device, scope.TenantID, scope.SiteID).Scan(&site, &certificate, &architecture, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	boundScope := Scope{TenantID: scope.TenantID, SiteID: site}
	if err = windowsSoftwarePermissions(ctx, tx, permissions, actor, boundScope, true); err != nil {
		return nil, err
	}
	var inventory string
	if err = tx.QueryRowContext(ctx, `SELECT oid FROM agents WHERE oid=$1 AND lower(os)='windows' AND agent_status IN ('Enabled','No contact') FOR UPDATE`, device).Scan(&inventory); err != nil {
		return nil, ErrConflict
	}
	rows, err := tx.QueryContext(ctx, `SELECT site_id FROM site_agents WHERE agent_id=$1 ORDER BY site_id LIMIT 2 FOR SHARE`, device)
	if err != nil {
		return nil, err
	}
	count := 0
	for rows.Next() {
		var edge int
		if rows.Scan(&edge) != nil || edge != site {
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
	// Lock the immutable approval against a concurrent permanent withdrawal.
	var packageID, kind, approvedArchitecture string
	err = tx.QueryRowContext(ctx, `SELECT package_id,kind,architecture FROM uem_software_versions WHERE id=$1 AND tenant_id=$2 AND withdrawn_at IS NULL FOR SHARE`, version, scope.TenantID).Scan(&packageID, &kind, &approvedArchitecture)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(kind, "windows-") || map[string]string{"amd64": "x86_64", "arm64": "arm64", "386": "x86"}[architecture] != approvedArchitecture {
		return nil, ErrConflict
	}
	expired, err := tx.QueryContext(ctx, `UPDATE uem_windows_software_requests SET status='expired',completed_at=clock_timestamp() WHERE agent_id=$1 AND status='prepared' AND expires_at<=clock_timestamp() RETURNING id,tenant_id,site_id`, device)
	if err != nil {
		return nil, err
	}
	type expiredPreparation struct {
		id    string
		scope Scope
	}
	var expirations []expiredPreparation
	for expired.Next() {
		var item expiredPreparation
		if err = expired.Scan(&item.id, &item.scope.TenantID, &item.scope.SiteID); err != nil {
			expired.Close()
			return nil, err
		}
		expirations = append(expirations, item)
	}
	err = expired.Err()
	expired.Close()
	if err != nil {
		return nil, err
	}
	for _, item := range expirations {
		if err = windowsRequestAudit(ctx, tx, item.scope, "system", "software.windows.request.expire", item.id); err != nil {
			return nil, err
		}
	}
	var busy bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_windows_software_requests WHERE agent_id=$1 AND status='prepared')`, device).Scan(&busy); err != nil {
		return nil, err
	}
	if busy {
		return nil, ErrConflict
	}
	deadline := time.Now().Add(time.Hour).Truncate(time.Second)
	if expiry.Before(deadline) {
		deadline = expiry.Truncate(time.Second)
	}
	if !deadline.After(time.Now().Add(time.Minute)) {
		return nil, ErrConflict
	}
	id := uuid.NewString()
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_windows_software_requests(id,tenant_id,site_id,agent_id,certificate_hash,package_id,version_id,request_id,operation,actor,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, id, scope.TenantID, site, device, certificate, packageID, version, requestID, operation, actor, deadline)
	if err != nil {
		return nil, err
	}
	if err = windowsRequestAudit(ctx, tx, boundScope, actor, "software.windows.request.prepare", id); err != nil {
		return nil, err
	}
	// Time can pass while waiting for an audit trigger or an inventory/approval
	// lock. A stale certificate must not authorize the final committed request.
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT revoked_at IS NULL AND certificate_expires_at>clock_timestamp() AND $2::timestamptz>clock_timestamp() FROM uem_agent_identities WHERE id=$1`, device, deadline).Scan(&active); err != nil {
		return nil, err
	}
	if !active {
		return nil, ErrConflict
	}
	result, err := scanWindowsSoftwareRequest(tx.QueryRowContext(ctx, `SELECT `+windowsRequestColumns+` FROM uem_windows_software_requests r WHERE r.id=$1`, id))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// CancelWindowsSoftwarePreparation requires rights in the recorded site even
// after an endpoint is revoked or moved. It can only cancel unsent preparation.
func (s *Store) CancelWindowsSoftwarePreparation(ctx context.Context, scope Scope, version, id, actor string, permissions *access.Store) error {
	if scope.Validate() != nil || permissions == nil || actor == "" {
		return access.ErrDenied
	}
	if !enrollment.ValidDeviceID(id) || !enrollment.ValidDeviceID(version) {
		return ErrWindowsSoftware
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = windowsSoftwarePermissions(ctx, tx, permissions, actor, scope, true); err != nil {
		return err
	}
	r, err := scanWindowsSoftwareRequest(tx.QueryRowContext(ctx, `SELECT `+windowsRequestColumns+` FROM uem_windows_software_requests r WHERE r.id=$1 AND r.version_id=$2 AND r.tenant_id=$3 AND ($4::bigint=0 OR r.site_id=$4) FOR UPDATE`, id, version, scope.TenantID, scope.SiteID))
	if err != nil {
		return err
	}
	bound := Scope{TenantID: r.TenantID, SiteID: r.SiteID}
	if err = windowsSoftwarePermissions(ctx, tx, permissions, actor, bound, true); err != nil {
		return err
	}
	if r.Status == "cancelled" {
		return tx.Commit()
	}
	if r.Status != "prepared" {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `UPDATE uem_windows_software_requests SET status='cancelled',completed_at=clock_timestamp() WHERE id=$1`, id); err != nil {
		return err
	}
	if err = windowsRequestAudit(ctx, tx, bound, actor, "software.windows.request.cancel", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ReadWindowsSoftwareRequests(ctx context.Context, scope Scope, version, query, after, before, actor string, permissions *access.Store) (*WindowsSoftwareRequestsPage, error) {
	if scope.Validate() != nil || permissions == nil || actor == "" {
		return nil, access.ErrDenied
	}
	query = strings.TrimSpace(query)
	if !enrollment.ValidDeviceID(version) || (after != "" && !enrollment.ValidDeviceID(after)) || (before != "" && !enrollment.ValidDeviceID(before)) || (query != "" && !validMacAppText(query, 128)) {
		return nil, ErrWindowsSoftware
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = windowsSoftwarePermissions(ctx, tx, permissions, actor, scope, false); err != nil {
		return nil, err
	}
	page := new(WindowsSoftwareRequestsPage)
	page.Version, err = softwareVersionTx(ctx, tx, scope, version)
	if err != nil {
		return nil, err
	}
	if page.Version.Platform != "windows" {
		return nil, ErrNotFound
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+windowsRequestColumns+` FROM uem_windows_software_requests r WHERE r.tenant_id=$1 AND r.version_id=$2 AND ($3::bigint=0 OR r.site_id=$3) AND ($4='' OR (r.created_at,r.id)<(SELECT created_at,id FROM uem_windows_software_requests WHERE id=NULLIF($4,'')::uuid AND tenant_id=$1 AND version_id=$2 AND ($3::bigint=0 OR site_id=$3))) ORDER BY r.created_at DESC,r.id DESC LIMIT 51`, scope.TenantID, version, scope.SiteID, before)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		r, e := scanWindowsSoftwareRequest(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		page.Requests = append(page.Requests, *r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(page.Requests) > 50 {
		page.NextRequest = page.Requests[49].ID
		page.Requests = page.Requests[:50]
	}
	var ready bool
	if err = tx.QueryRowContext(ctx, `SELECT to_regclass('uem_agent_identities') IS NOT NULL AND to_regclass('agents') IS NOT NULL AND to_regclass('site_agents') IS NOT NULL`).Scan(&ready); err != nil {
		return nil, err
	}
	if ready && page.Version.WithdrawnAt == nil {
		search := "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(query) + "%"
		rows, err = tx.QueryContext(ctx, `SELECT i.id,COALESCE(NULLIF(a.nickname,''),a.hostname),i.architecture,i.site_id FROM uem_agent_identities i JOIN sites s ON s.id=i.site_id AND s.tenant_sites=i.tenant_id JOIN agents a ON a.oid=i.id::text JOIN site_agents sa ON sa.agent_id=a.oid AND sa.site_id=i.site_id WHERE i.tenant_id=$1 AND ($2::bigint=0 OR i.site_id=$2) AND i.platform='windows' AND i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp()+interval '1 minute' AND lower(a.os)='windows' AND a.agent_status IN ('Enabled','No contact') AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1 AND i.architecture=$3 AND ($4='' OR i.id>(SELECT id FROM uem_agent_identities WHERE id=NULLIF($4,'')::uuid AND tenant_id=$1 AND ($2::bigint=0 OR site_id=$2))) AND ($5='' OR a.hostname ILIKE $6 OR a.nickname ILIKE $6 OR i.id::text ILIKE $6) ORDER BY i.id LIMIT 51`, scope.TenantID, scope.SiteID, map[string]string{"x86_64": "amd64", "arm64": "arm64", "x86": "386"}[page.Version.Architecture], after, query, search)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var target WindowsSoftwareTarget
			if err = rows.Scan(&target.ID, &target.Name, &target.Architecture, &target.SiteID); err != nil {
				rows.Close()
				return nil, err
			}
			page.Targets = append(page.Targets, target)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if len(page.Targets) > 50 {
			page.NextTarget = page.Targets[49].ID
			page.Targets = page.Targets[:50]
		}
	}
	if err = windowsRequestAudit(ctx, tx, scope, actor, "software.windows.requests.read", version); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}
