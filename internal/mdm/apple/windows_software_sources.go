package apple

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/software/winget"
)

type WindowsSoftwareSource struct {
	Expired                               bool
	ID, PackageID, SourceVersionID, Actor string
	Commit, ManifestPath, ManifestSHA256  string
	CreatedAt, ExpiresAt                  time.Time
	Approval                              *WindowsSoftwareSourceApproval
}

type WindowsSoftwareSourceApproval struct {
	ID, VersionID, Actor, ReviewHash string
	InstallerIndex                   int
	ApprovedAt                       time.Time
	WithdrawnAt                      *time.Time
}

type WindowsSoftwareSourceOption struct {
	winget.MSIOption
	ReviewHash string
}

type WindowsSoftwareSourceReview struct {
	Version        *SoftwareVersion
	Source         WindowsSoftwareSource
	Options        []WindowsSoftwareSourceOption
	Expired        bool
	InstallerCount int
}

type WindowsSoftwareSourcesPage struct {
	Focused bool
	Version *SoftwareVersion
	Sources []WindowsSoftwareSource
	Next    string
}

const windowsSourceColumns = `s.id,s.package_id,s.source_version_id,s.actor,s.source_commit,s.manifest_path,s.manifest_sha256,s.created_at,s.expires_at,s.encrypted_snapshot,s.expires_at<=clock_timestamp()`

type windowsSourceEnvelope struct {
	FormatVersion               int
	VersionID, PackageID, Actor string
	CreatedAt, ExpiresAt        time.Time
	Snapshot                    winget.Snapshot
}

func windowsSourceMutation(ctx context.Context, tx *sql.Tx, scope Scope, actor string, permissions *access.Store) error {
	if scope.Validate() != nil || scope.SiteID != 0 || actor == "" || permissions == nil {
		return access.ErrDenied
	}
	for _, capability := range []access.Capability{access.ReadSoftware, access.ManageSoftware} {
		if err := permissions.AuthorizeTransaction(ctx, tx, actor, capability, access.Scope{TenantID: scope.TenantID}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) windowsSourceInput(ctx context.Context, tx *sql.Tx, scope Scope, version string, active bool) (*SoftwareVersion, WindowsSoftwareInput, error) {
	var input WindowsSoftwareInput
	var sealed []byte
	var withdrawn sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT encrypted_definition,withdrawn_at FROM uem_software_versions WHERE id=$1 AND tenant_id=$2 AND kind='windows-winget' FOR SHARE`, version, scope.TenantID).Scan(&sealed, &withdrawn); err != nil {
		return nil, input, notFound(err)
	}
	if active && withdrawn.Valid {
		return nil, input, ErrConflict
	}
	plain, err := s.secrets.open(sealed, secretPurpose(scope.TenantID, version, "windows_software_definition"))
	defer clear(plain)
	if err != nil {
		return nil, input, ErrWindowsSoftware
	}
	var definition struct {
		Input     WindowsSoftwareInput     `json:"input"`
		Execution WindowsSoftwareExecution `json:"execution"`
	}
	if json.Unmarshal(plain, &definition) != nil {
		return nil, input, ErrWindowsSoftware
	}
	input = definition.Input
	input.Execution = definition.Execution
	canonical, err := input.canonical()
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plain) || input.Validate() != nil || input.Kind != "windows-winget" {
		return nil, input, ErrWindowsSoftware
	}
	v, err := softwareVersionTx(ctx, tx, scope, version)
	if err != nil {
		return nil, input, err
	}
	if !windowsSoftwareVersionMatches(*v, input) {
		return nil, input, ErrConflict
	}
	return v, input, nil
}

func windowsSoftwareVersionMatches(v SoftwareVersion, input WindowsSoftwareInput) bool {
	metadata, _ := json.Marshal(input.Metadata())
	stored, _ := json.Marshal(v.Windows)
	return v.Platform == "windows" && v.Kind == input.Kind && v.Name == input.Name && v.Identifier == input.Identifier && v.Version == input.Version && v.Architecture == input.Architecture && v.MinimumOS == input.MinimumOS && v.SHA256 == input.SHA256 && bytes.Equal(metadata, stored)
}

func sourceMSITarget(input WindowsSoftwareInput) winget.MSITarget {
	return winget.MSITarget{Architecture: map[string]string{"x86_64": "amd64", "arm64": "arm64"}[input.Architecture], MinimumOS: input.MinimumOS, Detection: enrollment.SoftwareDetection{Kind: input.Detection.Kind, ProductCode: input.Detection.ProductCode, UninstallKey: input.Detection.UninstallKey, RegistryView: input.Detection.RegistryView, Version: input.Detection.Version}}
}

func (s *Store) windowsSourceRecord(ctx context.Context, tx *sql.Tx, scope Scope, version, id string, input WindowsSoftwareInput) (*WindowsSoftwareSource, winget.Snapshot, error) {
	var r WindowsSoftwareSource
	var sealed []byte
	var snapshot winget.Snapshot
	if err := tx.QueryRowContext(ctx, `SELECT `+windowsSourceColumns+` FROM uem_windows_software_sources s WHERE s.id=$1 AND s.tenant_id=$2`, id, scope.TenantID).Scan(&r.ID, &r.PackageID, &r.SourceVersionID, &r.Actor, &r.Commit, &r.ManifestPath, &r.ManifestSHA256, &r.CreatedAt, &r.ExpiresAt, &sealed, &r.Expired); err != nil {
		return nil, snapshot, notFound(err)
	}
	// A retained request for another revision is a conflict, not a fresh fetch
	// followed by an opaque primary-key failure. Keep this lookup tenant-bound.
	if r.SourceVersionID != version {
		return nil, snapshot, ErrConflict
	}
	plain, err := s.secrets.open(sealed, secretPurpose(scope.TenantID, id, "windows_winget_source"))
	defer clear(plain)
	if err != nil || len(plain) > 1<<20 {
		return nil, snapshot, ErrWindowsSoftware
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	var envelope windowsSourceEnvelope
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, winget.Snapshot{}, ErrWindowsSoftware
	}
	snapshot = envelope.Snapshot
	canonical, err := json.Marshal(envelope)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plain) || envelope.FormatVersion != 1 || envelope.VersionID != r.SourceVersionID || envelope.PackageID != r.PackageID || envelope.Actor != r.Actor || !envelope.CreatedAt.Equal(r.CreatedAt) || !envelope.ExpiresAt.Equal(r.ExpiresAt) || snapshot.Coordinate != (winget.Coordinate{Identifier: input.Identifier, Version: input.Version}) || snapshot.Commit != r.Commit || snapshot.Path != r.ManifestPath || snapshot.SHA256 != r.ManifestSHA256 {
		return nil, winget.Snapshot{}, ErrWindowsSoftware
	}
	if _, err := snapshot.Inspect(); err != nil {
		return nil, winget.Snapshot{}, ErrWindowsSoftware
	}
	return &r, snapshot, nil
}

func sourceReviewHash(tenant int, r WindowsSoftwareSource, index int, plan enrollment.SoftwarePlan, actor string) (string, error) {
	digest, err := plan.Digest()
	if err != nil {
		return "", ErrWindowsSoftware
	}
	return sourceReviewDigest(tenant, r, index, digest, actor)
}

func sourceReviewDigest(tenant int, r WindowsSoftwareSource, index int, digest, actor string) (string, error) {
	data, err := json.Marshal(struct {
		Tenant, Index                              int
		ID, Version, Manifest, Commit, Plan, Actor string
		Expires                                    int64
	}{tenant, index, r.ID, r.SourceVersionID, r.ManifestSHA256, r.Commit, digest, actor, r.ExpiresAt.Unix()})
	if err != nil {
		return "", ErrWindowsSoftware
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func derivedWindowsMSI(input WindowsSoftwareInput, plan enrollment.SoftwarePlan) (WindowsSoftwareInput, error) {
	input.Kind = "windows-msi"
	input.MinimumOS = plan.MinimumOS
	input.SHA256 = plan.Artifact.SHA256
	input.SuccessCodes = slices.Clone(plan.SuccessCodes)
	input.RebootCodes = slices.Clone(plan.RebootCodes)
	input.Execution = WindowsSoftwareExecution{SourceURL: plan.Artifact.URL}
	if input.Validate() != nil {
		return WindowsSoftwareInput{}, ErrWindowsSoftware
	}
	return input, nil
}

func (s *Store) sourceApproval(ctx context.Context, tx *sql.Tx, scope Scope, r *WindowsSoftwareSource, input WindowsSoftwareInput, snapshot winget.Snapshot) error {
	var a WindowsSoftwareSourceApproval
	var sourceVersion, sourcePackage string
	err := tx.QueryRowContext(ctx, `SELECT a.id,a.version_id,a.actor,a.installer_index,a.review_hash,a.approved_at,v.withdrawn_at,a.source_version_id,a.package_id FROM uem_windows_software_source_approvals a LEFT JOIN uem_software_versions v ON v.id=a.version_id AND v.tenant_id=a.tenant_id AND v.package_id=a.package_id WHERE a.source_id=$1 AND a.tenant_id=$2`, r.ID, scope.TenantID).Scan(&a.ID, &a.VersionID, &a.Actor, &a.InstallerIndex, &a.ReviewHash, &a.ApprovedAt, &a.WithdrawnAt, &sourceVersion, &sourcePackage)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if sourceVersion != r.SourceVersionID || sourcePackage != r.PackageID || a.ApprovedAt.Before(r.CreatedAt) || !a.ApprovedAt.Before(r.ExpiresAt) {
		return ErrWindowsSoftware
	}
	plan, err := winget.MSIPlan(snapshot, a.InstallerIndex, sourceMSITarget(input), "install")
	if err != nil || a.Actor != r.Actor {
		return ErrWindowsSoftware
	}
	hash, err := sourceReviewHash(scope.TenantID, *r, a.InstallerIndex, plan, a.Actor)
	if err != nil || hash != a.ReviewHash {
		return ErrWindowsSoftware
	}
	derived, err := derivedWindowsMSI(input, plan)
	if err != nil {
		return err
	}
	want, err := derived.canonical()
	defer clear(want)
	if err != nil {
		return err
	}
	var sealed []byte
	var actor, approval, packageID string
	if err := tx.QueryRowContext(ctx, `SELECT encrypted_definition,approved_by,approval_request_id,package_id FROM uem_software_versions WHERE id=$1 AND tenant_id=$2`, a.VersionID, scope.TenantID).Scan(&sealed, &actor, &approval, &packageID); err != nil {
		return err
	}
	got, err := s.secrets.open(sealed, secretPurpose(scope.TenantID, a.VersionID, "windows_software_definition"))
	defer clear(got)
	if err != nil || !bytes.Equal(got, want) || actor != a.Actor || approval != a.ID || packageID != r.PackageID {
		return ErrWindowsSoftware
	}
	v, err := softwareVersionTx(ctx, tx, scope, a.VersionID)
	if err != nil {
		return err
	}
	if !windowsSoftwareVersionMatches(*v, derived) || v.ApprovedAt.Before(r.CreatedAt) || v.ApprovedAt.After(a.ApprovedAt) {
		return ErrWindowsSoftware
	}
	r.Approval = &a
	return nil
}

// fetch is a trusted backend dependency. The console supplies the fixed HTTPS
// Microsoft source; HTTP clients can never submit a snapshot or source URL.
func (s *Store) ResolveWindowsSoftwareSource(ctx context.Context, scope Scope, version, id, actor string, permissions *access.Store, fetch func(context.Context, winget.Coordinate) (*winget.Snapshot, error)) (*WindowsSoftwareSource, error) {
	if !enrollment.ValidDeviceID(version) || !enrollment.ValidDeviceID(id) {
		return nil, ErrWindowsSoftware
	}
	if fetch == nil {
		return nil, winget.ErrSource
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	// Authorize and audit before sending even a public coordinate to the source.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = windowsSourceMutation(ctx, tx, scope, actor, permissions); err != nil {
		return nil, err
	}
	v, input, err := s.windowsSourceInput(ctx, tx, scope, version, false)
	if err != nil {
		return nil, err
	}
	prior, snapshot, err := s.windowsSourceRecord(ctx, tx, scope, version, id, input)
	if err == nil {
		defer clear(snapshot.Content)
		if prior.Actor != actor {
			return nil, ErrConflict
		}
		if err = s.sourceApproval(ctx, tx, scope, prior, input, snapshot); err != nil {
			return nil, err
		}
		if err = windowsRequestAudit(ctx, tx, scope, actor, "software.windows.source.read", id); err != nil {
			return nil, err
		}
		return prior, tx.Commit()
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if v.WithdrawnAt != nil {
		return nil, ErrConflict
	}
	if err = windowsRequestAudit(ctx, tx, scope, actor, "software.windows.source.request", id); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	result, err := fetch(ctx, winget.Coordinate{Identifier: input.Identifier, Version: input.Version})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, winget.ErrSource
	}
	captured := *result
	captured.Content = slices.Clone(result.Content)
	defer clear(captured.Content)
	if captured.Coordinate != (winget.Coordinate{Identifier: input.Identifier, Version: input.Version}) {
		return nil, winget.ErrManifest
	}
	if _, err = captured.Inspect(); err != nil {
		return nil, err
	}
	// No identity, catalog, permission or database lock is held during HTTPS.
	tx, err = s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = windowsSourceMutation(ctx, tx, scope, actor, permissions); err != nil {
		return nil, err
	}
	v, input, err = s.windowsSourceInput(ctx, tx, scope, version, false)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "windows-source:"+strconv.Itoa(scope.TenantID)+":"+id); err != nil {
		return nil, err
	}
	prior, snapshot, err = s.windowsSourceRecord(ctx, tx, scope, version, id, input)
	if err == nil {
		defer clear(snapshot.Content)
		if prior.Actor != actor {
			return nil, ErrConflict
		}
		if err = s.sourceApproval(ctx, tx, scope, prior, input, snapshot); err != nil {
			return nil, err
		}
		return prior, tx.Commit()
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if v.WithdrawnAt != nil {
		return nil, ErrConflict
	}
	var createdAt, expiresAt time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp(),date_trunc('second',clock_timestamp()+interval '15 minutes')`).Scan(&createdAt, &expiresAt); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(windowsSourceEnvelope{FormatVersion: 1, VersionID: version, PackageID: v.PackageID, Actor: actor, CreatedAt: createdAt.UTC(), ExpiresAt: expiresAt.UTC(), Snapshot: captured})
	defer clear(plain)
	if err != nil || len(plain) > 1<<20 {
		return nil, ErrWindowsSoftware
	}
	sealed, err := s.secrets.seal(plain, secretPurpose(scope.TenantID, id, "windows_winget_source"))
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_windows_software_sources(id,tenant_id,package_id,source_version_id,actor,source_commit,manifest_path,manifest_sha256,encrypted_snapshot,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, id, scope.TenantID, v.PackageID, version, actor, captured.Commit, captured.Path, captured.SHA256, sealed, createdAt, expiresAt)
	if err != nil {
		return nil, err
	}
	if err = windowsRequestAudit(ctx, tx, scope, actor, "software.windows.source.capture", id); err != nil {
		return nil, err
	}
	prior, snapshot, err = s.windowsSourceRecord(ctx, tx, scope, version, id, input)
	defer clear(snapshot.Content)
	if err != nil {
		return nil, err
	}
	return prior, tx.Commit()
}

func (s *Store) ReviewWindowsSoftwareSource(ctx context.Context, scope Scope, version, id, actor string, permissions *access.Store) (*WindowsSoftwareSourceReview, error) {
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
	if err = windowsSourceMutation(ctx, tx, scope, actor, permissions); err != nil {
		return nil, err
	}
	v, input, err := s.windowsSourceInput(ctx, tx, scope, version, false)
	if err != nil {
		return nil, err
	}
	r, snapshot, err := s.windowsSourceRecord(ctx, tx, scope, version, id, input)
	defer clear(snapshot.Content)
	if err != nil {
		return nil, err
	}
	if r.Actor != actor {
		return nil, access.ErrDenied
	}
	if err = s.sourceApproval(ctx, tx, scope, r, input, snapshot); err != nil {
		return nil, err
	}
	var expired bool
	if err = tx.QueryRowContext(ctx, `SELECT $1<=clock_timestamp()`, r.ExpiresAt).Scan(&expired); err != nil {
		return nil, err
	}
	manifest, err := snapshot.Inspect()
	if err != nil {
		return nil, ErrWindowsSoftware
	}
	page := &WindowsSoftwareSourceReview{Version: v, Source: *r, Expired: expired, InstallerCount: len(manifest.Installers)}
	if !expired && r.Approval == nil && v.WithdrawnAt == nil {
		options, err := winget.MSIOptions(snapshot, sourceMSITarget(input))
		if err != nil {
			return nil, ErrWindowsSoftware
		}
		for _, option := range options {
			hash, err := sourceReviewDigest(scope.TenantID, *r, option.Index, option.PlanDigest, actor)
			if err != nil {
				return nil, err
			}
			page.Options = append(page.Options, WindowsSoftwareSourceOption{MSIOption: option, ReviewHash: hash})
		}
	}
	if err = windowsRequestAudit(ctx, tx, scope, actor, "software.windows.source.review", id); err != nil {
		return nil, err
	}
	return page, tx.Commit()
}

func (s *Store) ApproveWindowsSoftwareSource(ctx context.Context, scope Scope, version, id, approvalID string, index int, reviewHash, actor string, permissions *access.Store) (*SoftwareVersion, error) {
	if !enrollment.ValidDeviceID(version) || !enrollment.ValidDeviceID(id) || !enrollment.ValidDeviceID(approvalID) || index < 0 || index > 255 || !validWindowsDigest(reviewHash) {
		return nil, ErrWindowsSoftware
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = windowsSourceMutation(ctx, tx, scope, actor, permissions); err != nil {
		return nil, err
	}
	v, input, err := s.windowsSourceInput(ctx, tx, scope, version, false)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "windows-source:"+strconv.Itoa(scope.TenantID)+":"+id); err != nil {
		return nil, err
	}
	r, snapshot, err := s.windowsSourceRecord(ctx, tx, scope, version, id, input)
	defer clear(snapshot.Content)
	if err != nil {
		return nil, err
	}
	if r.Actor != actor {
		return nil, access.ErrDenied
	}
	if err = s.sourceApproval(ctx, tx, scope, r, input, snapshot); err != nil {
		return nil, err
	}
	if r.Approval != nil {
		a := r.Approval
		if a.ID != approvalID || a.Actor != actor || a.InstallerIndex != index || a.ReviewHash != reviewHash {
			return nil, ErrConflict
		}
		derived, err := softwareVersionTx(ctx, tx, scope, a.VersionID)
		if err != nil {
			return nil, err
		}
		return derived, tx.Commit()
	}
	var expired bool
	if err = tx.QueryRowContext(ctx, `SELECT $1<=clock_timestamp()`, r.ExpiresAt).Scan(&expired); err != nil {
		return nil, err
	}
	if expired || v.WithdrawnAt != nil {
		return nil, ErrConflict
	}
	plan, err := winget.MSIPlan(snapshot, index, sourceMSITarget(input), "install")
	if err != nil {
		return nil, ErrWindowsSoftware
	}
	hash, err := sourceReviewHash(scope.TenantID, *r, index, plan, actor)
	if err != nil || hash != reviewHash {
		return nil, ErrConflict
	}
	derivedInput, err := derivedWindowsMSI(input, plan)
	if err != nil {
		return nil, err
	}
	// A source approval cannot reattribute an already published ordinary revision
	// or a different source's revision by reusing its generic approval request ID.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "software-approval:"+strconv.Itoa(scope.TenantID)+":"+approvalID); err != nil {
		return nil, err
	}
	var used bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_software_versions WHERE tenant_id=$1 AND approval_request_id=$2)`, scope.TenantID, approvalID).Scan(&used); err != nil {
		return nil, err
	}
	if used {
		return nil, ErrConflict
	}
	derived, err := s.publishWindowsSoftwareTx(ctx, tx, scope, approvalID, derivedInput, actor)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_windows_software_source_approvals(id,tenant_id,package_id,source_version_id,source_id,version_id,actor,installer_index,review_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, approvalID, scope.TenantID, v.PackageID, version, id, derived.ID, actor, index, reviewHash)
	if err != nil {
		return nil, err
	}
	if err = windowsRequestAudit(ctx, tx, scope, actor, "software.windows.source.approve", id); err != nil {
		return nil, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT $1<=clock_timestamp()`, r.ExpiresAt).Scan(&expired); err != nil {
		return nil, err
	}
	if expired {
		return nil, ErrConflict
	}
	return derived, tx.Commit()
}

func (s *Store) ReadWindowsSoftwareSources(ctx context.Context, scope Scope, version, before, actor string, permissions *access.Store) (*WindowsSoftwareSourcesPage, error) {
	if !enrollment.ValidDeviceID(version) || before != "" && !enrollment.ValidDeviceID(before) {
		return nil, ErrWindowsSoftware
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.softwareReadTransaction(ctx, scope, actor, permissions)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	v, input, err := s.windowsSourceInput(ctx, tx, scope, version, false)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM uem_windows_software_sources WHERE tenant_id=$1 AND source_version_id=$2 AND ($3='' OR (created_at,id)<(SELECT created_at,id FROM uem_windows_software_sources WHERE id=NULLIF($3,'')::uuid AND tenant_id=$1 AND source_version_id=$2)) ORDER BY created_at DESC,id DESC LIMIT 51`, scope.TenantID, version, before)
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
	page := &WindowsSoftwareSourcesPage{Version: v}
	if len(ids) > 50 {
		page.Next = ids[49]
		ids = ids[:50]
	}
	for _, id := range ids {
		r, snapshot, err := s.windowsSourceRecord(ctx, tx, scope, version, id, input)
		if err != nil {
			return nil, err
		}
		err = s.sourceApproval(ctx, tx, scope, r, input, snapshot)
		clear(snapshot.Content)
		if err != nil {
			return nil, err
		}
		page.Sources = append(page.Sources, *r)
	}
	if err = windowsRequestAudit(ctx, tx, scope, actor, "software.windows.source.read", version); err != nil {
		return nil, err
	}
	return page, tx.Commit()
}

func (s *Store) readWindowsDerivedSource(ctx context.Context, tx *sql.Tx, scope Scope, v SoftwareVersion) (*WindowsSoftwareSource, error) {
	var sourceVersion, id string
	err := tx.QueryRowContext(ctx, `SELECT source_version_id,source_id FROM uem_windows_software_source_approvals WHERE version_id=$1 AND tenant_id=$2`, v.ID, scope.TenantID).Scan(&sourceVersion, &id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_, input, err := s.windowsSourceInput(ctx, tx, scope, sourceVersion, false)
	if err != nil {
		return nil, err
	}
	r, snapshot, err := s.windowsSourceRecord(ctx, tx, scope, sourceVersion, id, input)
	defer clear(snapshot.Content)
	if err != nil {
		return nil, err
	}
	if err = s.sourceApproval(ctx, tx, scope, r, input, snapshot); err != nil {
		return nil, err
	}
	if r.Approval == nil || r.Approval.VersionID != v.ID || r.PackageID != v.PackageID {
		return nil, ErrWindowsSoftware
	}
	return r, nil
}

func (s *Store) ReadWindowsSoftwareSource(ctx context.Context, scope Scope, version, id, actor string, permissions *access.Store) (*WindowsSoftwareSourcesPage, error) {
	if !enrollment.ValidDeviceID(version) || !enrollment.ValidDeviceID(id) {
		return nil, ErrWindowsSoftware
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.softwareReadTransaction(ctx, scope, actor, permissions)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	v, input, err := s.windowsSourceInput(ctx, tx, scope, version, false)
	if err != nil {
		return nil, err
	}
	r, snapshot, err := s.windowsSourceRecord(ctx, tx, scope, version, id, input)
	defer clear(snapshot.Content)
	if err != nil {
		return nil, err
	}
	if err = s.sourceApproval(ctx, tx, scope, r, input, snapshot); err != nil {
		return nil, err
	}
	if err = windowsRequestAudit(ctx, tx, scope, actor, "software.windows.source.read", id); err != nil {
		return nil, err
	}
	return &WindowsSoftwareSourcesPage{Version: v, Sources: []WindowsSoftwareSource{*r}, Focused: true}, tx.Commit()
}
