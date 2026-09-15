package apple

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type WindowsSoftwareDispatchReview struct {
	Request                WindowsSoftwareRequest
	Version                *SoftwareVersion
	TargetName, ReviewHash string
	ExpiresAt              time.Time
}

func windowsExecutablePlan(data []byte, operation string) (enrollment.SoftwarePlan, error) {
	var definition struct {
		Input     WindowsSoftwareInput     `json:"input"`
		Execution WindowsSoftwareExecution `json:"execution"`
	}
	var plan enrollment.SoftwarePlan
	if len(data) == 0 || len(data) > 32<<10 || json.Unmarshal(data, &definition) != nil {
		return plan, ErrWindowsSoftware
	}
	input := definition.Input
	input.Execution = definition.Execution
	canonical, err := input.canonical()
	defer clear(canonical)
	if err != nil || !bytes.Equal(data, canonical) || input.Validate() != nil || (operation != "install" && operation != "remove") || (input.Kind != "windows-msi" && input.Kind != "windows-exe" && input.Kind != "windows-burn") {
		return plan, ErrWindowsSoftware
	}
	plan = enrollment.SoftwarePlan{Kind: input.Kind, Operation: operation, Identifier: input.Identifier, Version: input.Version, Architecture: map[string]string{"x86_64": "amd64", "arm64": "arm64"}[input.Architecture], MinimumOS: input.MinimumOS, Detection: enrollment.SoftwareDetection{Kind: input.Detection.Kind, ProductCode: input.Detection.ProductCode, UninstallKey: input.Detection.UninstallKey, RegistryView: input.Detection.RegistryView, Version: input.Detection.Version}, SuccessCodes: slices.Clone(input.SuccessCodes), RebootCodes: slices.Clone(input.RebootCodes)}
	if input.Kind == "windows-msi" {
		if operation == "install" {
			plan.Artifact = enrollment.SoftwareArtifact{URL: input.Execution.SourceURL, SHA256: input.SHA256, Format: "msi"}
			plan.MSIProperties = maps.Clone(input.Execution.MSIProperties)
		}
	} else {
		plan.Artifact = enrollment.SoftwareArtifact{URL: input.Execution.SourceURL, SHA256: input.SHA256, Format: "exe"}
		plan.Arguments = slices.Clone(input.Execution.InstallArguments)
		if operation == "remove" {
			plan.Artifact.URL, plan.Artifact.SHA256 = input.Execution.UninstallURL, input.Execution.UninstallSHA256
			plan.Arguments = slices.Clone(input.Execution.UninstallArguments)
		}
	}
	if !plan.Valid() {
		return enrollment.SoftwarePlan{}, ErrWindowsSoftware
	}
	return plan, nil
}

// windowsDispatchReview locks identity/recipient before inventory and request,
// matching the worker. The private plan is returned only inside the trusted
// transaction; the review projection cannot expose its URL or arguments.
func (s *Store) windowsDispatchReview(ctx context.Context, tx *sql.Tx, scope Scope, version, id, actor string, permissions *access.Store) (*WindowsSoftwareDispatchReview, enrollment.SoftwarePlan, error) {
	var empty enrollment.SoftwarePlan
	r, err := scanWindowsSoftwareRequest(tx.QueryRowContext(ctx, `SELECT `+windowsRequestColumns+` FROM uem_windows_software_requests r WHERE r.id=$1 AND r.version_id=$2 AND r.tenant_id=$3 AND ($4::bigint=0 OR r.site_id=$4)`, id, version, scope.TenantID, scope.SiteID))
	if err != nil {
		return nil, empty, err
	}
	bound := Scope{TenantID: r.TenantID, SiteID: r.SiteID}
	if err = windowsSoftwarePermissions(ctx, tx, permissions, actor, bound, true); err != nil {
		return nil, empty, err
	}
	channel, _ := registry.NewAccessStore(s.db)
	recipient, certificate, err := channel.SoftwareRecipient(ctx, tx, registry.Scope{TenantID: r.TenantID, SiteID: r.SiteID}, r.AgentID)
	if err != nil {
		return nil, empty, ErrConflict
	}
	var name, architecture string
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(NULLIF(a.nickname,''),a.hostname),i.architecture FROM agents a JOIN uem_agent_identities i ON a.oid=i.id::text WHERE a.oid=$1 AND lower(a.os)='windows' AND a.agent_status IN ('Enabled','No contact') FOR UPDATE OF a`, r.AgentID).Scan(&name, &architecture)
	if err != nil {
		return nil, empty, ErrConflict
	}
	rows, err := tx.QueryContext(ctx, `SELECT site_id FROM site_agents WHERE agent_id=$1 ORDER BY site_id LIMIT 2 FOR SHARE`, r.AgentID)
	if err != nil {
		return nil, empty, err
	}
	count := 0
	for rows.Next() {
		var site int
		if rows.Scan(&site) != nil || site != r.SiteID {
			rows.Close()
			return nil, empty, ErrConflict
		}
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, empty, err
	}
	if count != 1 {
		return nil, empty, ErrConflict
	}
	r, err = scanWindowsSoftwareRequest(tx.QueryRowContext(ctx, `SELECT `+windowsRequestColumns+` FROM uem_windows_software_requests r WHERE r.id=$1 AND r.version_id=$2 AND r.tenant_id=$3 AND r.site_id=$4 FOR UPDATE`, id, version, r.TenantID, r.SiteID))
	if err != nil || r.Status != "prepared" {
		return nil, empty, ErrConflict
	}
	var original string
	if err = tx.QueryRowContext(ctx, `SELECT certificate_hash FROM uem_windows_software_requests WHERE id=$1`, id).Scan(&original); err != nil || original != recipient.Identity.CertificateHash {
		return nil, empty, ErrConflict
	}
	var sealed []byte
	err = tx.QueryRowContext(ctx, `SELECT encrypted_definition FROM uem_software_versions WHERE id=$1 AND tenant_id=$2 AND withdrawn_at IS NULL FOR SHARE`, version, r.TenantID).Scan(&sealed)
	if err != nil {
		return nil, empty, ErrConflict
	}
	plain, err := s.secrets.open(sealed, secretPurpose(r.TenantID, version, "windows_software_definition"))
	defer clear(plain)
	if err != nil {
		return nil, empty, ErrWindowsSoftware
	}
	plan, err := windowsExecutablePlan(plain, r.Operation)
	if err != nil || plan.Architecture != architecture {
		return nil, empty, ErrWindowsSoftware
	}
	if !recipient.Supports(plan) {
		return nil, empty, ErrConflict
	}
	v, err := softwareVersionTx(ctx, tx, bound, version)
	if err != nil {
		return nil, empty, err
	}
	if v.Platform != "windows" || v.Identifier != plan.Identifier || v.Kind != plan.Kind || v.Version != plan.Version || v.MinimumOS != plan.MinimumOS || map[string]string{"x86_64": "amd64", "arm64": "arm64"}[v.Architecture] != plan.Architecture {
		return nil, empty, ErrConflict
	}
	if plan.Kind == "windows-burn" {
		v.WinGetSource, err = s.readWindowsDerivedSource(ctx, tx, bound, *v)
		if err != nil || v.WinGetSource == nil {
			return nil, empty, ErrWindowsSoftware
		}
	}
	metadata := v.Windows
	if metadata.Kind != plan.Kind || metadata.Detection.Kind != plan.Detection.Kind || metadata.Detection.ProductCode != plan.Detection.ProductCode || metadata.Detection.UninstallKey != plan.Detection.UninstallKey || metadata.Detection.RegistryView != plan.Detection.RegistryView || metadata.Detection.Version != plan.Detection.Version || !slices.Equal(metadata.SuccessCodes, plan.SuccessCodes) || !slices.Equal(metadata.RebootCodes, plan.RebootCodes) {
		return nil, empty, ErrConflict
	}
	if plan.Operation == "install" && v.SHA256 != plan.Artifact.SHA256 || plan.Operation == "remove" && (plan.Kind == "windows-exe" || plan.Kind == "windows-burn") && metadata.UninstallSHA256 != plan.Artifact.SHA256 {
		return nil, empty, ErrConflict
	}
	deadline := r.ExpiresAt.Truncate(time.Second)
	if !deadline.After(time.Now().Add(time.Minute)) || deadline.After(certificate.NotAfter) {
		return nil, empty, ErrConflict
	}
	var busy bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_software_tasks WHERE device_id=$1 AND reconciliation_id IS NULL AND (status IN ('delivered','uncertain','restart_required') OR status='pending' AND expires_at>clock_timestamp()))`, r.AgentID).Scan(&busy); err != nil {
		return nil, empty, err
	}
	if busy {
		return nil, empty, ErrConflict
	}
	hash, err := plan.Digest()
	if err != nil {
		return nil, empty, ErrWindowsSoftware
	}
	boundReview := struct {
		Request, Revision, Device, Operation, Certificate, Recipient, Plan, Actor string
		Tenant, Site                                                              int
		Expires                                                                   int64
	}{r.ID, version, r.AgentID, r.Operation, original, recipient.ID, hash, actor, r.TenantID, r.SiteID, deadline.Unix()}
	data, _ := json.Marshal(boundReview)
	sum := sha256.Sum256(data)
	clear(data)
	return &WindowsSoftwareDispatchReview{Request: *r, Version: v, TargetName: name, ReviewHash: hex.EncodeToString(sum[:]), ExpiresAt: deadline}, plan, nil
}

func (s *Store) ReviewWindowsSoftwareDispatch(ctx context.Context, scope Scope, version, id, actor string, permissions *access.Store) (*WindowsSoftwareDispatchReview, error) {
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
	if err = windowsSoftwarePermissions(ctx, tx, permissions, actor, scope, true); err != nil {
		return nil, err
	}
	review, _, err := s.windowsDispatchReview(ctx, tx, scope, version, id, actor, permissions)
	if err != nil {
		return nil, err
	}
	if err = windowsRequestAudit(ctx, tx, Scope{TenantID: review.Request.TenantID, SiteID: review.Request.SiteID}, actor, "software.windows.dispatch.review", id); err != nil {
		return nil, err
	}
	return review, tx.Commit()
}

func (s *Store) DispatchWindowsSoftware(ctx context.Context, scope Scope, version, id, dispatchID, reviewHash, actor string, permissions *access.Store) (*registry.SoftwareTaskStatus, error) {
	if scope.Validate() != nil || actor == "" || permissions == nil {
		return nil, access.ErrDenied
	}
	if !enrollment.ValidDeviceID(version) || !enrollment.ValidDeviceID(id) || !enrollment.ValidDeviceID(dispatchID) || !validWindowsDigest(reviewHash) {
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
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "windows-software-dispatch:"+strconv.Itoa(scope.TenantID)+":"+dispatchID); err != nil {
		return nil, err
	}
	channel, _ := registry.NewAccessStore(s.db)
	var priorID, priorVersion, priorActor, priorHash string
	var site int
	err = tx.QueryRowContext(ctx, `SELECT preparation_id,version_id,actor,review_hash,site_id FROM uem_windows_software_dispatches WHERE id=$1 AND tenant_id=$2`, dispatchID, scope.TenantID).Scan(&priorID, &priorVersion, &priorActor, &priorHash, &site)
	if err == nil {
		bound := Scope{TenantID: scope.TenantID, SiteID: site}
		if priorID != id || priorVersion != version || priorActor != actor || priorHash != reviewHash || (scope.SiteID != 0 && scope.SiteID != site) {
			return nil, ErrConflict
		}
		if err = windowsSoftwarePermissions(ctx, tx, permissions, actor, bound, true); err != nil {
			return nil, err
		}
		status, err := channel.ReadSoftwareTaskInTransaction(ctx, tx, registry.Scope{TenantID: scope.TenantID, SiteID: site}, dispatchID)
		if err != nil {
			return nil, err
		}
		return status, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	review, plan, err := s.windowsDispatchReview(ctx, tx, scope, version, id, actor, permissions)
	if err != nil {
		return nil, err
	}
	if review.ReviewHash != reviewHash {
		return nil, ErrConflict
	}
	r := review.Request
	bound := Scope{TenantID: r.TenantID, SiteID: r.SiteID}
	registryScope := registry.Scope{TenantID: r.TenantID, SiteID: r.SiteID}
	if _, err = s.agentRegistry.QueueSoftwareTaskInTransaction(ctx, tx, registryScope, r.AgentID, dispatchID, id, version, plan, review.ExpiresAt, actor); err != nil {
		return nil, ErrConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_windows_software_dispatches(id,tenant_id,site_id,agent_id,version_id,preparation_id,actor,review_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, dispatchID, r.TenantID, r.SiteID, r.AgentID, version, id, actor, reviewHash, review.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE uem_windows_software_requests SET status='dispatched',completed_at=clock_timestamp() WHERE id=$1 AND status='prepared'`, id); err != nil {
		return nil, err
	}
	if err = windowsRequestAudit(ctx, tx, bound, actor, "software.windows.dispatch.queue", dispatchID); err != nil {
		return nil, err
	}
	var current bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_identities i JOIN uem_windows_software_requests r ON r.agent_id=i.id AND r.tenant_id=i.tenant_id AND r.site_id=i.site_id AND r.certificate_hash=i.certificate_hash WHERE r.id=$1 AND i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp() AND $2::timestamptz>clock_timestamp())`, r.ID, review.ExpiresAt).Scan(&current); err != nil || !current {
		return nil, ErrConflict
	}
	status, err := channel.ReadSoftwareTaskInTransaction(ctx, tx, registryScope, dispatchID)
	if err != nil {
		return nil, err
	}
	return status, tx.Commit()
}

func (s *Store) CancelWindowsSoftwareDispatch(ctx context.Context, scope Scope, version, id, actor string, permissions *access.Store) error {
	if scope.Validate() != nil || actor == "" || permissions == nil {
		return access.ErrDenied
	}
	if !enrollment.ValidDeviceID(version) || !enrollment.ValidDeviceID(id) {
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
	var task string
	var site int
	err = tx.QueryRowContext(ctx, `SELECT id,site_id FROM uem_windows_software_dispatches WHERE preparation_id=$1 AND version_id=$2 AND tenant_id=$3 AND ($4::bigint=0 OR site_id=$4)`, id, version, scope.TenantID, scope.SiteID).Scan(&task, &site)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	bound := Scope{TenantID: scope.TenantID, SiteID: site}
	if err = windowsSoftwarePermissions(ctx, tx, permissions, actor, bound, true); err != nil {
		return err
	}
	channel, _ := registry.NewAccessStore(s.db)
	if _, err = channel.CancelSoftwareTaskInTransaction(ctx, tx, registry.Scope{TenantID: scope.TenantID, SiteID: site}, task, actor); err != nil {
		return ErrConflict
	}
	return tx.Commit()
}
