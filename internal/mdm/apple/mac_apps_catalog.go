package apple

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// SoftwareVersion is safe to use in inventory and catalog pages. Download URLs
// are purpose-bound encrypted values available only while issuing a command.
type SoftwareVersion struct {
	ID, PackageID, Platform, Name, Identifier, Version string
	Architecture, MinimumOS, SHA256, ApprovedBy        string
	SingleApp                                          bool
	ApprovedAt                                         time.Time
	WithdrawnAt                                        *time.Time
}

const softwareVersionColumns = `v.id,v.package_id,p.platform,v.name,p.identifier,v.version,v.architecture,v.minimum_os,v.artifact_sha256,v.single_app,v.approved_by,v.approved_at,v.withdrawn_at`
const softwareVersionFrom = ` FROM uem_software_versions v JOIN uem_software_packages p ON p.id=v.package_id AND p.tenant_id=v.tenant_id `

func (s *Store) SoftwareVersion(ctx context.Context, scope Scope, id string) (*SoftwareVersion, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	return scanSoftwareVersion(s.db.QueryRowContext(ctx, `SELECT `+softwareVersionColumns+softwareVersionFrom+`WHERE v.tenant_id=$1 AND v.id=$2`, scope.TenantID, id))
}

func scanSoftwareVersion(row scanner) (*SoftwareVersion, error) {
	var v SoftwareVersion
	err := row.Scan(&v.ID, &v.PackageID, &v.Platform, &v.Name, &v.Identifier, &v.Version, &v.Architecture, &v.MinimumOS, &v.SHA256, &v.SingleApp, &v.ApprovedBy, &v.ApprovedAt, &v.WithdrawnAt)
	return &v, notFound(err)
}

// Catalog pagination does not expose the encrypted source or infer cross-tenant
// cursor timestamps. Site readers see the organization's approved catalog.
func (s *Store) SoftwareVersions(ctx context.Context, scope Scope, before string) ([]SoftwareVersion, string, error) {
	return s.softwareVersions(ctx, scope, before, "", false, "")
}

// SearchApprovedMacApplications supports bounded, credential-free selection of
// required apps and replacement revisions without loading the complete catalog.
func (s *Store) SearchApprovedMacApplications(ctx context.Context, scope Scope, before, query, packageID string) ([]SoftwareVersion, string, error) {
	return s.softwareVersions(ctx, scope, before, query, true, packageID)
}

func (s *Store) softwareVersions(ctx context.Context, scope Scope, before, query string, approvedOnly bool, packageID string) ([]SoftwareVersion, string, error) {
	if err := scope.Validate(); err != nil {
		return nil, "", err
	}
	query = strings.TrimSpace(query)
	if len(query) > 128 {
		return nil, "", ErrMacApp
	}
	var pkg any
	if packageID != "" {
		id, err := uuid.Parse(packageID)
		if err != nil || id == uuid.Nil || id.String() != packageID {
			return nil, "", ErrMacApp
		}
		pkg = packageID
	}
	var stamp any
	var cursor any
	if before != "" {
		id, err := uuid.Parse(before)
		if err != nil || id == uuid.Nil || id.String() != before {
			return nil, "", ErrMacApp
		}
		var at time.Time
		if err = s.db.QueryRowContext(ctx, `SELECT approved_at FROM uem_software_versions WHERE tenant_id=$1 AND id=$2`, scope.TenantID, before).Scan(&at); err != nil {
			return nil, "", notFound(err)
		}
		stamp, cursor = at, before
	}
	pattern := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(query) + "%"
	rows, err := s.db.QueryContext(ctx, `SELECT `+softwareVersionColumns+softwareVersionFrom+`WHERE v.tenant_id=$1 AND ($2::timestamptz IS NULL OR (v.approved_at,v.id)<($2,$3::uuid)) AND (v.name ILIKE $4 OR p.identifier ILIKE $4) AND (NOT $5::boolean OR (v.withdrawn_at IS NULL AND p.platform='macos' AND v.kind='macos-pkg')) AND ($6::uuid IS NULL OR v.package_id=$6) ORDER BY v.approved_at DESC,v.id DESC LIMIT 101`, scope.TenantID, stamp, cursor, pattern, approvedOnly, pkg)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := []SoftwareVersion{}
	for rows.Next() {
		v, err := scanSoftwareVersion(rows)
		if err != nil {
			return nil, "", err
		}
		items = append(items, *v)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) > 100 {
		items = items[:100]
		next = items[len(items)-1].ID
	}
	return items, next, nil
}

func (s *Store) PublishMacAppPackage(ctx context.Context, scope Scope, input MacAppPackageInput, actor string, permissions *access.Store) (*SoftwareVersion, error) {
	if permissions == nil {
		return nil, access.ErrDenied
	}
	return s.publishMacAppPackage(ctx, scope, input, actor, permissions)
}

func (s *Store) publishMacAppPackage(ctx context.Context, scope Scope, input MacAppPackageInput, actor string, permissions *access.Store) (*SoftwareVersion, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if scope.SiteID != 0 || actor == "" {
		return nil, access.ErrDenied
	}
	if err := input.Validate(); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if permissions != nil {
		if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageSoftware, access.Scope{TenantID: scope.TenantID}); err != nil {
			return nil, err
		}
	}
	var packageID string
	err = tx.QueryRowContext(ctx, `INSERT INTO uem_software_packages(id,tenant_id,platform,identifier) VALUES($1,$2,'macos',$3) ON CONFLICT(tenant_id,platform,identifier) DO UPDATE SET identifier=excluded.identifier RETURNING id`, uuid.NewString(), scope.TenantID, input.Identifier).Scan(&packageID)
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	url := []byte(input.SourceURL)
	defer clear(url)
	sealed, err := s.secrets.seal(url, secretPurpose(scope.TenantID, id, "software_url"))
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_software_versions(id,tenant_id,package_id,name,version,kind,architecture,minimum_os,artifact_sha256,encrypted_url,single_app,approved_by) VALUES($1,$2,$3,$4,$5,'macos-pkg',$6,$7,$8,$9,$10,$11)`, id, scope.TenantID, packageID, input.Name, input.Version, input.Architecture, input.MinimumOS, input.SHA256, sealed, input.SingleApp, actor)
	if err != nil {
		return nil, err
	}
	if err = audit(ctx, tx, scope.TenantID, actor, "apple.software.version.publish", id); err != nil {
		return nil, err
	}
	v, err := scanSoftwareVersion(tx.QueryRowContext(ctx, `SELECT `+softwareVersionColumns+softwareVersionFrom+`WHERE v.id=$1`, id))
	if err != nil {
		return nil, err
	}
	return v, tx.Commit()
}

func (s *Store) WithdrawSoftwareVersion(ctx context.Context, scope Scope, id, actor string, permissions *access.Store) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if permissions == nil || scope.SiteID != 0 {
		return access.ErrDenied
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageSoftware, access.Scope{TenantID: scope.TenantID}); err != nil {
		return err
	}
	var withdrawn *time.Time
	if err = tx.QueryRowContext(ctx, `SELECT withdrawn_at FROM uem_software_versions WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, scope.TenantID, id).Scan(&withdrawn); err != nil {
		return notFound(err)
	}
	if withdrawn != nil {
		return tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, `UPDATE uem_software_versions SET withdrawn_at=clock_timestamp() WHERE id=$1`, id); err != nil {
		return err
	}
	if err = audit(ctx, tx, scope.TenantID, actor, "apple.software.version.withdraw", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) macAppArtifactTx(ctx context.Context, tx *sql.Tx, tenant int, id string) (*SoftwareVersion, MacAppPackageInput, error) {
	v, err := scanSoftwareVersion(tx.QueryRowContext(ctx, `SELECT `+softwareVersionColumns+softwareVersionFrom+`WHERE v.tenant_id=$1 AND v.id=$2 AND v.kind='macos-pkg' AND p.platform='macos' FOR SHARE OF v`, tenant, id))
	if err != nil {
		return nil, MacAppPackageInput{}, err
	}
	if v.WithdrawnAt != nil {
		return nil, MacAppPackageInput{}, ErrConflict
	}
	var data []byte
	if err = tx.QueryRowContext(ctx, `SELECT encrypted_url FROM uem_software_versions WHERE id=$1`, id).Scan(&data); err != nil {
		return nil, MacAppPackageInput{}, err
	}
	data, err = s.secrets.open(data, secretPurpose(tenant, id, "software_url"))
	if err != nil {
		return nil, MacAppPackageInput{}, errors.New("approved package source is unavailable")
	}
	defer clear(data)
	p := MacAppPackageInput{Name: v.Name, Identifier: v.Identifier, Version: v.Version, Architecture: v.Architecture, MinimumOS: v.MinimumOS, SHA256: v.SHA256, SourceURL: string(data), SingleApp: v.SingleApp}
	return v, p, p.Validate()
}
