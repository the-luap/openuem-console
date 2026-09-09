package apple

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/ade"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var (
	ErrADE        = errors.New("Automated Device Enrollment is unavailable")
	ErrADEAccount = errors.New("the token belongs to a different Apple organization or server")
)

// ADEServer is public connection metadata, without credentials, cursor or keys.
type ADEServer struct {
	ID, Name, Status                                                                               string
	AppleServerID, AppleServerName, AppleOrganizationID, AppleOrganizationName, AppleAdministrator string
	CertificateExpiresAt                                                                           time.Time
	TokenExpiresAt, VerifiedAt, SyncedAt, AttemptedAt, NextSyncAt, RetryAfter                      *time.Time
	SyncMode, SyncError                                                                            string
	Pages, Assigned                                                                                int64
}

const adeServerColumns = `id,name,status,COALESCE(apple_server_id::text,''),apple_server_name,apple_organization_id,apple_organization_name,apple_administrator,certificate_expires_at,token_expires_at,verified_at,synced_at,attempted_at,next_sync_at,retry_after,sync_mode,sync_error,page_count,(SELECT count(*) FROM mdm_apple_ade_devices d WHERE d.server_id=mdm_apple_ade_servers.id AND d.assigned)`

func scanADEServer(row scanner) (ADEServer, error) {
	var v ADEServer
	err := row.Scan(&v.ID, &v.Name, &v.Status, &v.AppleServerID, &v.AppleServerName, &v.AppleOrganizationID, &v.AppleOrganizationName, &v.AppleAdministrator, &v.CertificateExpiresAt, &v.TokenExpiresAt, &v.VerifiedAt, &v.SyncedAt, &v.AttemptedAt, &v.NextSyncAt, &v.RetryAfter, &v.SyncMode, &v.SyncError, &v.Pages, &v.Assigned)
	return v, notFound(err)
}

func (s *Store) ADEServers(ctx context.Context, tenant int) ([]ADEServer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+adeServerColumns+` FROM mdm_apple_ade_servers WHERE tenant_id=$1 ORDER BY created_at,id`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []ADEServer{}
	for rows.Next() {
		v, err := scanADEServer(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, v)
	}
	return list, rows.Err()
}

func (s *Store) adeTx(ctx context.Context, tenant int, actor string, authorize func(context.Context, *sql.Tx) error) (*sql.Tx, error) {
	if tenant <= 0 || actor == "" || len(actor) > 255 {
		return nil, ErrADE
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if authorize != nil {
		if err = authorize(ctx, tx); err != nil {
			tx.Rollback()
			return nil, err
		}
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627920,$1::integer)`, tenant); err != nil {
		tx.Rollback()
		return nil, err
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)`, tenant).Scan(&exists); err != nil || !exists {
		tx.Rollback()
		return nil, ErrNotFound
	}
	return tx, nil
}

func adePermission(p *access.Store, tenant int, actor string) func(context.Context, *sql.Tx) error {
	return func(ctx context.Context, tx *sql.Tx) error {
		if p == nil {
			return access.ErrDenied
		}
		return p.AuthorizeTransaction(ctx, tx, actor, access.ManageCertificates, access.Scope{TenantID: tenant})
	}
}

func (s *Store) CreateADEServer(ctx context.Context, tenant int, name, actor string, p *access.Store) (string, error) {
	return s.createADEServer(ctx, tenant, name, actor, adePermission(p, tenant, actor))
}

func (s *Store) createADEServer(ctx context.Context, tenant int, name, actor string, authorize func(context.Context, *sql.Tx) error) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 255 || !utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl) {
		return "", ErrADE
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tx, err := s.adeTx(ctx, tenant, actor, authorize)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_ade_servers WHERE tenant_id=$1`, tenant).Scan(&count); err != nil {
		return "", err
	}
	if count >= 16 {
		return "", ErrADE
	}
	id := uuid.NewString()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return "", ErrADE
	}
	serial, err := certificateSerial()
	if err != nil {
		return "", ErrADE
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "OpenUEM ADE " + id}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), KeyUsage: x509.KeyUsageKeyEncipherment, SignatureAlgorithm: x509.SHA256WithRSA}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", ErrADE
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", ErrADE
	}
	defer clear(private)
	sealed, err := s.secrets.seal(private, secretPurpose(tenant, id, "ade_private_key"))
	if err != nil {
		return "", ErrADE
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_ade_servers(id,tenant_id,name,certificate,private_key,certificate_expires_at) VALUES($1,$2,$3,$4,$5,$6)`, id, tenant, name, der, sealed, template.NotAfter)
	if err != nil {
		return "", err
	}
	if err = audit(ctx, tx, tenant, actor, "apple.ade.server.create", id); err != nil {
		return "", err
	}
	return id, tx.Commit()
}

func (s *Store) ADEServerCertificate(ctx context.Context, tenant int, id, actor string, p *access.Store) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := s.adeTx(ctx, tenant, actor, adePermission(p, tenant, actor))
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var der []byte
	if err = tx.QueryRowContext(ctx, `SELECT certificate FROM mdm_apple_ade_servers WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&der); err != nil {
		return nil, notFound(err)
	}
	if err = audit(ctx, tx, tenant, actor, "apple.ade.certificate.download", id); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func (s *Store) ImportADEToken(ctx context.Context, tenant int, id string, data []byte, actor string, p *access.Store) error {
	return s.importADEToken(ctx, tenant, id, data, actor, adePermission(p, tenant, actor))
}

func (s *Store) importADEToken(ctx context.Context, tenant int, id string, data []byte, actor string, authorize func(context.Context, *sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	tx, err := s.adeTx(ctx, tenant, actor, authorize)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var certDER, sealedKey []byte
	var oldServer, oldOrganization string
	var oldExpiry *time.Time
	var retryAfter *time.Time
	err = tx.QueryRowContext(ctx, `SELECT certificate,private_key,COALESCE(apple_server_id::text,''),apple_organization_id,token_expires_at,retry_after FROM mdm_apple_ade_servers WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).Scan(&certDER, &sealedKey, &oldServer, &oldOrganization, &oldExpiry, &retryAfter)
	if err != nil {
		return notFound(err)
	}
	if retryAfter != nil && retryAfter.After(time.Now()) {
		return &ade.RetryError{After: time.Until(*retryAfter)}
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return ErrADE
	}
	private, err := s.secrets.open(sealedKey, secretPurpose(tenant, id, "ade_private_key"))
	if err != nil {
		return ErrADE
	}
	defer clear(private)
	parsed, err := x509.ParsePKCS8PrivateKey(private)
	if err != nil {
		return ErrADE
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return ErrADE
	}
	token, err := ade.DecryptToken(data, cert, key, time.Now())
	if err != nil {
		return ade.ErrToken
	}
	defer token.Close()
	if oldExpiry != nil && token.ExpiresAt().Before(*oldExpiry) {
		return ade.ErrToken
	}
	if s.adeService == nil {
		return ErrADE
	}
	client := s.adeService(token)
	if client == nil {
		return ErrADE
	}
	defer client.Close()
	network, stop := context.WithTimeout(ctx, 15*time.Second)
	account, err := client.Account(network)
	stop()
	if err != nil {
		var retry *ade.RetryError
		if errors.As(err, &retry) {
			deadline := time.Now().Add(max(time.Second, retry.After))
			if _, updateErr := tx.ExecContext(ctx, `UPDATE mdm_apple_ade_servers SET retry_after=$3,sync_error='throttled',next_sync_at=CASE WHEN status='connected' THEN GREATEST(next_sync_at,$3) ELSE next_sync_at END WHERE tenant_id=$1 AND id=$2`, tenant, id, deadline); updateErr != nil {
				return updateErr
			}
			if auditErr := auditOutcome(ctx, tx, tenant, actor, "apple.ade.token.verification", id, "deferred"); auditErr != nil {
				return auditErr
			}
			if commitErr := tx.Commit(); commitErr != nil {
				return commitErr
			}
		}
		return err
	}
	if oldServer != "" && (oldServer != account.ServerID || oldOrganization != account.OrganizationID) {
		return ErrADEAccount
	}
	if !token.ExpiresAt().After(time.Now().Add(time.Minute)) || !time.Now().Before(cert.NotAfter) {
		return ade.ErrToken
	}
	plain := token.Bytes()
	defer clear(plain)
	sealed, err := s.secrets.seal(plain, secretPurpose(tenant, id, "ade_token"))
	if err != nil {
		return ErrADE
	}
	var duplicate bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_ade_servers WHERE apple_server_id=$1 AND id<>$2)`, account.ServerID, id).Scan(&duplicate); err != nil {
		return err
	}
	if duplicate {
		return ErrADEAccount
	}
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_servers SET status='connected',token=$3,token_hash=$4,token_expires_at=$5,token_revision=token_revision+1,apple_server_id=$6,apple_server_name=$7,apple_organization_id=$8,apple_organization_name=$9,apple_administrator=$10,verified_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, tenant, id, sealed, digest(plain), token.ExpiresAt(), account.ServerID, account.ServerName, account.OrganizationID, account.OrganizationName, account.Administrator)
	if err != nil {
		return err
	}
	if err = resetADEFetch(ctx, tx, tenant, id); err != nil {
		return err
	}
	if err = audit(ctx, tx, tenant, actor, "apple.ade.token.import", id); err != nil {
		return err
	}
	return tx.Commit()
}

func resetADEFetch(ctx context.Context, tx *sql.Tx, tenant int, id string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM mdm_apple_ade_fetch WHERE tenant_id=$1 AND server_id=$2`, tenant, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mdm_apple_ade_cursors WHERE server_id=$1`, id); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_ade_servers SET sync_mode='full',sync_generation=gen_random_uuid(),sync_cursor='',cursor_updated_at=NULL,page_count=0,next_sync_at=GREATEST(clock_timestamp(),retry_after),sync_error='' WHERE tenant_id=$1 AND id=$2`, tenant, id)
	return err
}

func (s *Store) ChangeADEServer(ctx context.Context, tenant int, id, operation, actor string, p *access.Store) error {
	return s.changeADEServer(ctx, tenant, id, operation, actor, adePermission(p, tenant, actor))
}

func (s *Store) changeADEServer(ctx context.Context, tenant int, id, operation, actor string, authorize func(context.Context, *sql.Tx) error) error {
	if operation != "sync" && operation != "reload" && operation != "disable" {
		return ErrADE
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := s.adeTx(ctx, tenant, actor, authorize)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	var expiry *time.Time
	if err = tx.QueryRowContext(ctx, `SELECT status,token_expires_at FROM mdm_apple_ade_servers WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).Scan(&status, &expiry); err != nil {
		return notFound(err)
	}
	if operation == "disable" {
		if err = resetADEFetch(ctx, tx, tenant, id); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_servers SET status='disabled',token=NULL,token_hash='',token_revision=token_revision+1,next_sync_at=NULL,sync_error='',updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, tenant, id)
	} else {
		if status != "connected" || expiry == nil || !expiry.After(time.Now().Add(time.Minute)) {
			return ade.ErrToken
		}
		if operation == "reload" {
			err = resetADEFetch(ctx, tx, tenant, id)
		} else {
			_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_servers SET next_sync_at=GREATEST(clock_timestamp(),retry_after) WHERE tenant_id=$1 AND id=$2`, tenant, id)
		}
	}
	if err != nil {
		return err
	}
	if err = audit(ctx, tx, tenant, actor, "apple.ade.server."+operation, id); err != nil {
		return err
	}
	return tx.Commit()
}
