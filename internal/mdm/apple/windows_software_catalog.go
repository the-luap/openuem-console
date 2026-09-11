package apple

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// PublishWindowsSoftware approves immutable execution intent. It does not send
// legacy package commands or imply that an individually enrolled agent supports
// this catalog adapter. Replays must match the original actor and exact intent.
func (s *Store) PublishWindowsSoftware(ctx context.Context, scope Scope, requestID string, input WindowsSoftwareInput, actor string, permissions *access.Store) (*SoftwareVersion, error) {
	if scope.Validate() != nil || scope.SiteID != 0 || actor == "" || permissions == nil {
		return nil, access.ErrDenied
	}
	id, err := uuid.Parse(requestID)
	if err != nil || id == uuid.Nil || id.String() != requestID || input.Validate() != nil {
		return nil, ErrWindowsSoftware
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageSoftware, access.Scope{TenantID: scope.TenantID}); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "software-approval:"+strconv.Itoa(scope.TenantID)+":"+requestID); err != nil {
		return nil, err
	}
	canonical, err := input.canonical()
	if err != nil {
		return nil, ErrWindowsSoftware
	}
	defer clear(canonical)
	var previousID, previousActor string
	var previous []byte
	err = tx.QueryRowContext(ctx, `SELECT id,approved_by,encrypted_definition FROM uem_software_versions WHERE tenant_id=$1 AND approval_request_id=$2`, scope.TenantID, requestID).Scan(&previousID, &previousActor, &previous)
	if err == nil {
		defer clear(previous)
		plain, openErr := s.secrets.open(previous, secretPurpose(scope.TenantID, previousID, "windows_software_definition"))
		defer clear(plain)
		if openErr != nil || previousActor != actor || !bytes.Equal(plain, canonical) {
			return nil, ErrConflict
		}
		v, err := softwareVersionTx(ctx, tx, scope, previousID)
		if err != nil {
			return nil, err
		}
		return v, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var packageID string
	err = tx.QueryRowContext(ctx, `INSERT INTO uem_software_packages(id,tenant_id,platform,identifier) VALUES($1,$2,'windows',$3) ON CONFLICT(tenant_id,platform,identifier) DO UPDATE SET identifier=excluded.identifier RETURNING id`, uuid.NewString(), scope.TenantID, input.Identifier).Scan(&packageID)
	if err != nil {
		return nil, err
	}
	versionID := uuid.NewString()
	sealed, err := s.secrets.seal(canonical, secretPurpose(scope.TenantID, versionID, "windows_software_definition"))
	if err != nil {
		return nil, err
	}
	metadata, err := json.Marshal(input.Metadata())
	if err != nil {
		return nil, ErrWindowsSoftware
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_software_versions(id,tenant_id,package_id,name,version,kind,architecture,minimum_os,artifact_sha256,single_app,approved_by,encrypted_definition,windows_metadata,approval_request_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),false,$10,$11,$12,$13)`, versionID, scope.TenantID, packageID, input.Name, input.Version, input.Kind, input.Architecture, input.MinimumOS, input.SHA256, actor, sealed, metadata, requestID)
	if err != nil {
		return nil, err
	}
	if err = audit(ctx, tx, scope.TenantID, actor, "software.windows.version.publish", versionID); err != nil {
		return nil, err
	}
	v, err := softwareVersionTx(ctx, tx, scope, versionID)
	if err != nil {
		return nil, err
	}
	return v, tx.Commit()
}

func softwareVersionTx(ctx context.Context, tx *sql.Tx, scope Scope, id string) (*SoftwareVersion, error) {
	v, err := scanSoftwareVersion(tx.QueryRowContext(ctx, `SELECT `+softwareVersionColumns+softwareVersionFrom+`WHERE v.tenant_id=$1 AND v.id=$2`, scope.TenantID, id))
	if err != nil {
		return nil, err
	}
	return v, nil
}
