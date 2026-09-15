package inventory

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

// Installation status is a coherent snapshot of retained evidence. It never
// consults a device, decrypts a source or depends on present enrollment ownership.
type NetbirdInstallationStatus struct {
	Request      *NetbirdInstallation
	Package      NetbirdInstallationPackage
	Preparation  *NetbirdInstallationPreparation
	Delivery     *NetbirdInstallationDelivery
	DispatchStop *NetbirdInstallationDispatchStop
	Resolution   *NetbirdInstallationResolution
}

func (s NetbirdInstallationStatus) State() string {
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
	case s.Preparation != nil:
		switch s.Preparation.Outcome {
		case "prepared":
			return "prepared"
		case "pending":
			return "preparation_pending"
		case "unconfirmed":
			return "preparation_unconfirmed"
		default:
			return "preparation_rejected"
		}
	default:
		return "queued"
	}
}

func scanInstallationPackage(row interface{ Scan(...any) error }) (NetbirdInstallationPackage, error) {
	var p NetbirdInstallationPackage
	err := row.Scan(&p.ID, &p.TenantID, &p.Platform, &p.Architecture, &p.Format, &p.PackageID, &p.Version, &p.Size, &p.SHA256, &p.Digest)
	return p, err
}

const installationPackageColumns = `p.id::text,p.tenant_id,p.platform,p.architecture,p.format,p.package_id,p.version,p.size,p.sha256,p.digest`

func readInstallationStatus(ctx context.Context, tx *sql.Tx, scope access.Scope, device, id string) (*NetbirdInstallationStatus, error) {
	r, err := scanInstallation(tx.QueryRowContext(ctx, `SELECT `+installationColumns+` FROM uem_netbird_installations WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR SHARE`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out := &NetbirdInstallationStatus{Request: r}
	out.Package, err = scanInstallationPackage(tx.QueryRowContext(ctx, `SELECT `+installationPackageColumns+` FROM uem_netbird_packages p WHERE p.id=$1 AND p.tenant_id=$2 AND p.digest=$3`, r.ApprovalID, scope.TenantID, r.ApprovalDigest))
	if err != nil {
		return nil, err
	}
	out.Preparation, err = readInstallationPreparation(ctx, tx, id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	out.Delivery, err = readInstallationDelivery(ctx, tx, id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	out.DispatchStop, err = readInstallationDispatchStop(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	out.Resolution, err = readInstallationResolution(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *NetbirdInstallationStore) Status(parent context.Context, actor string, scope access.Scope, device, id string) (*NetbirdInstallationStatus, error) {
	if parent == nil || !canonicalRequestID(device) || !canonicalRequestID(id) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.ReadSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out, err := readInstallationStatus(ctx, tx, scope, device, id)
	if err != nil {
		return nil, err
	}
	if err = installationAudit(ctx, tx, actor, out.Request, "read", "recorded"); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

type NetbirdInstallationHistory struct {
	Requests []*NetbirdInstallationStatus
	Next     string
}

func (s *NetbirdInstallationStore) History(parent context.Context, actor string, scope access.Scope, device, before string) (*NetbirdInstallationHistory, error) {
	if parent == nil || !canonicalRequestID(device) || before != "" && !canonicalRequestID(before) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.ReadSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var at time.Time
	if before != "" {
		err = tx.QueryRowContext(ctx, `SELECT requested_at FROM uem_netbird_installations WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4`, before, device, scope.TenantID, scope.SiteID).Scan(&at)
		if errors.Is(err, sql.ErrNoRows) {
			err = ErrNotFound
		}
		if err != nil {
			return nil, err
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT id::text FROM uem_netbird_installations WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND ($4='' OR (requested_at,id)<($5,nullif($4,'')::uuid)) ORDER BY requested_at DESC,id DESC LIMIT 21`, device, scope.TenantID, scope.SiteID, before, at)
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
	out := &NetbirdInstallationHistory{Requests: []*NetbirdInstallationStatus{}}
	if len(ids) > 20 {
		ids = ids[:20]
		out.Next = ids[19]
	}
	for _, id := range ids {
		v, err := readInstallationStatus(ctx, tx, scope, device, id)
		if err != nil {
			return nil, err
		}
		out.Requests = append(out.Requests, v)
	}
	if err = installationAudit(ctx, tx, actor, &NetbirdInstallation{DeviceID: device, Scope: scope}, "read", "recorded"); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

type NetbirdInstallationChoices struct {
	Target       ManualTarget
	Architecture string
	Packages     []NetbirdInstallationPackage
	Next         string
}

// Choices exposes only target-matching approved artifact metadata to site
// operators. Organization verification text and private source data stay private.
func (s *NetbirdInstallationStore) Choices(parent context.Context, actor string, scope access.Scope, device, after string) (*NetbirdInstallationChoices, error) {
	if parent == nil || !canonicalRequestID(device) || after != "" && !canonicalRequestID(after) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.AssignSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if !s.individual {
		return nil, ErrNetbirdOperationNotReady
	}
	manual := &ManualExecutionStore{db: s.packages.db, permissions: s.packages.permissions, individual: true}
	target, err := manual.target(ctx, tx, scope, device)
	if err != nil {
		return nil, err
	}
	if target.Platform != "macos" && target.Platform != "linux" {
		return nil, ErrManualUnsupported
	}
	out := &NetbirdInstallationChoices{Target: target, Packages: []NetbirdInstallationPackage{}}
	var platform string
	err = tx.QueryRowContext(ctx, `SELECT platform,architecture FROM uem_agent_identities WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR SHARE`, device, scope.TenantID, scope.SiteID).Scan(&platform, &out.Architecture)
	if err != nil {
		return nil, err
	}
	if platform != target.Platform {
		return nil, ErrNetbirdOperationChanged
	}
	if after != "" {
		var exists bool
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_netbird_packages WHERE id=$1 AND tenant_id=$2 AND platform=$3 AND architecture=$4)`, after, scope.TenantID, platform, out.Architecture).Scan(&exists)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, ErrNotFound
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+installationPackageColumns+` FROM uem_netbird_packages p WHERE p.tenant_id=$1 AND p.platform=$2 AND p.architecture=$3 AND NOT EXISTS(SELECT 1 FROM uem_netbird_package_revocations WHERE approval_id=p.id) AND ($4='' OR p.id>nullif($4,'')::uuid) ORDER BY p.id LIMIT 51`, scope.TenantID, platform, out.Architecture, after)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		p, err := scanInstallationPackage(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out.Packages = append(out.Packages, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(out.Packages) > 50 {
		out.Packages = out.Packages[:50]
		out.Next = out.Packages[49].ID
	}
	if err = installationAudit(ctx, tx, actor, &NetbirdInstallation{DeviceID: device, Scope: scope}, "review", "recorded"); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}
