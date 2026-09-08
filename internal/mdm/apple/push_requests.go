package apple

import (
	"bytes"
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

	"github.com/google/uuid"
)

// PushRequest contains administrator metadata only. Neither the private key nor
// the CSR is returned by list operations. A CSR is not a vendor-signed request
// accepted by Apple's Push Certificates Portal.
type PushRequest struct {
	ID            string
	Organization  string
	PublicURL     string
	AppleAccount  string
	ExpectedTopic string
	BaseRevision  int64
	Status        string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

func (r PushRequest) Pending() bool {
	return r.Status == "pending" && time.Now().Before(r.ExpiresAt)
}

func (r PushRequest) State() string {
	if r.Status == "pending" && !r.Pending() {
		return "expired"
	}
	return r.Status
}

const pushRequestColumns = `id,organization,public_url,apple_account,expected_topic,base_revision,status,created_at,expires_at`

func scanPushRequest(row scanner) (*PushRequest, error) {
	var r PushRequest
	err := row.Scan(&r.ID, &r.Organization, &r.PublicURL, &r.AppleAccount, &r.ExpectedTopic, &r.BaseRevision, &r.Status, &r.CreatedAt, &r.ExpiresAt)
	return &r, notFound(err)
}

// SettingsMetadata reads the public setup summary without decrypting credentials.
// Callers must restrict AppleAccount to organization certificate administrators.
func (s *Store) SettingsMetadata(ctx context.Context, tenant int) (*Settings, error) {
	var c Settings
	err := s.db.QueryRowContext(ctx, `SELECT tenant_id,public_url,organization,topic,push_expires_at,apple_account FROM mdm_apple_settings WHERE tenant_id=$1`, tenant).Scan(&c.TenantID, &c.PublicURL, &c.Organization, &c.Topic, &c.PushExpiresAt, &c.AppleAccount)
	return &c, notFound(err)
}

func (s *Store) pushRequestTx(ctx context.Context, tenant int, actor string) (*sql.Tx, error) {
	if tenant <= 0 || actor == "" {
		return nil, errors.New("an organization and administrator are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627902,$1::integer)`, tenant); err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}

// CreatePushRequest generates a fresh key per request under the same lock used
// by credential replacement. The key never leaves encrypted instance storage.
func (s *Store) CreatePushRequest(ctx context.Context, tenant int, organization, publicURL, account, actor string) (*PushRequest, error) {
	c := Settings{TenantID: tenant, Organization: strings.TrimSpace(organization), PublicURL: strings.TrimSpace(publicURL)}
	if err := validatePushOrganization(&c); err != nil {
		return nil, err
	}
	account = strings.TrimSpace(account)
	if account == "" || len(account) > 320 || strings.ContainsFunc(account, unicode.IsControl) {
		return nil, errors.New("record the responsible Apple account (up to 320 characters)")
	}
	tx, err := s.pushRequestTx(ctx, tenant, actor)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var active int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_push_requests WHERE tenant_id=$1 AND status='pending' AND expires_at>clock_timestamp()`, tenant).Scan(&active); err != nil {
		return nil, err
	}
	if active >= 5 {
		return nil, errors.New("revoke an unused push certificate request before creating another (limit 5)")
	}
	var revision int64
	var topic, oldURL string
	err = tx.QueryRowContext(ctx, `SELECT push_revision,topic,public_url FROM mdm_apple_settings WHERE tenant_id=$1`, tenant).Scan(&revision, &topic, &oldURL)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil && oldURL != c.PublicURL {
		return nil, errors.New("a renewal request must use the existing public management URL")
	}
	id := uuid.NewString()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "OpenUEM MDM Push " + id, Organization: []string{c.Organization}},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(keyDER)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer clear(keyPEM)
	sealed, err := s.secrets.seal(keyPEM, secretPurpose(tenant, "push_request/"+id, "key"))
	if err != nil {
		return nil, err
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	r, err := scanPushRequest(tx.QueryRowContext(ctx, `INSERT INTO mdm_apple_push_requests(id,tenant_id,organization,public_url,apple_account,expected_topic,base_revision,csr,encrypted_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING `+pushRequestColumns, id, tenant, c.Organization, c.PublicURL, account, topic, revision, csr, sealed))
	if err != nil {
		return nil, err
	}
	if err = audit(ctx, tx, tenant, actor, "apple.push_request.create", id); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}

// PushRequests returns bounded recent history for authorized administrators.
func (s *Store) PushRequests(ctx context.Context, tenant int) ([]PushRequest, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+pushRequestColumns+` FROM mdm_apple_push_requests WHERE tenant_id=$1 ORDER BY created_at DESC,id LIMIT 25`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	requests := []PushRequest{}
	for rows.Next() {
		r, err := scanPushRequest(rows)
		if err != nil {
			return nil, err
		}
		requests = append(requests, *r)
	}
	return requests, rows.Err()
}

func lockPushRequest(ctx context.Context, tx *sql.Tx, tenant int, id string) (*PushRequest, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrNotFound
	}
	return scanPushRequest(tx.QueryRowContext(ctx, `SELECT `+pushRequestColumns+` FROM mdm_apple_push_requests WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id))
}

func livePushRequest(ctx context.Context, tx *sql.Tx, tenant int, id string) (*PushRequest, error) {
	r, err := lockPushRequest(ctx, tx, tenant, id)
	if err != nil {
		return nil, err
	}
	var live bool
	if err = tx.QueryRowContext(ctx, `SELECT status='pending' AND expires_at>clock_timestamp() FROM mdm_apple_push_requests WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&live); err != nil {
		return nil, err
	}
	if !live {
		return nil, ErrConflict
	}
	return r, nil
}

// PushRequestCSR exports only the public PKCS#10 input for an authorized vendor.
func (s *Store) PushRequestCSR(ctx context.Context, tenant int, id, actor string) ([]byte, error) {
	tx, err := s.pushRequestTx(ctx, tenant, actor)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = livePushRequest(ctx, tx, tenant, id); err != nil {
		return nil, err
	}
	var csr []byte
	if err = tx.QueryRowContext(ctx, `SELECT csr FROM mdm_apple_push_requests WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&csr); err != nil {
		return nil, err
	}
	if err = audit(ctx, tx, tenant, actor, "apple.push_request.csr_download", id); err != nil {
		return nil, err
	}
	return csr, tx.Commit()
}

func (s *Store) RevokePushRequest(ctx context.Context, tenant int, id, actor string) error {
	tx, err := s.pushRequestTx(ctx, tenant, actor)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := lockPushRequest(ctx, tx, tenant, id)
	if err != nil {
		return err
	}
	// Allow an administrator to remove an expired key even while the worker is
	// disabled. Completed imports cannot be revoked through this request API.
	if r.Status != "pending" {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_push_requests SET status='revoked',encrypted_key=NULL,completed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, tenant, id); err != nil {
		return err
	}
	if err = audit(ctx, tx, tenant, actor, "apple.push_request.revoke", id); err != nil {
		return err
	}
	return tx.Commit()
}

// ImportPushCertificate uses the selected request's key, never the newest key.
// Validation, settings replacement, request consumption and audit are atomic.
// This performs local validation; it does not claim APNs connectivity or issuance.
func (s *Store) ImportPushCertificate(ctx context.Context, tenant int, id string, certificate []byte, actor string) error {
	if err := certificateOnlyPEM(certificate); err != nil {
		return err
	}
	tx, err := s.pushRequestTx(ctx, tenant, actor)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := livePushRequest(ctx, tx, tenant, id)
	if err != nil {
		return err
	}
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT push_revision FROM mdm_apple_settings WHERE tenant_id=$1`, tenant).Scan(&revision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if r.BaseRevision != revision {
		return ErrConflict
	}
	var sealed []byte
	if err = tx.QueryRowContext(ctx, `SELECT encrypted_key FROM mdm_apple_push_requests WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&sealed); err != nil {
		return err
	}
	key, err := s.secrets.open(sealed, secretPurpose(tenant, "push_request/"+r.ID, "key"))
	if err != nil {
		return errors.New("the stored push request key could not be opened")
	}
	defer clear(key)
	c := Settings{TenantID: tenant, Organization: r.Organization, PublicURL: r.PublicURL, AppleAccount: r.AppleAccount, PushKey: key, PushCertificate: certificate}
	if err = validatePushSettings(&c); err != nil {
		return err
	}
	if r.ExpectedTopic != "" && r.ExpectedTopic != c.Topic {
		return errors.New("APNs renewal must preserve the existing push topic; renew the existing Apple portal entry")
	}
	// CA generation in the shared replacement can take time. Check expiry again
	// after it returns, before committing any part of the replacement.
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_push_requests SET status='imported',encrypted_key=NULL,completed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, tenant, id); err != nil {
		return err
	}
	if err = s.configurePushTx(ctx, tx, c, actor, true); err != nil {
		return err
	}
	var unexpired bool
	if err = tx.QueryRowContext(ctx, `SELECT expires_at>clock_timestamp() FROM mdm_apple_push_requests WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&unexpired); err != nil {
		return err
	}
	if !unexpired {
		return ErrConflict
	}
	if err = audit(ctx, tx, tenant, actor, "apple.push_request.import", id); err != nil {
		return err
	}
	return tx.Commit()
}

func certificateOnlyPEM(data []byte) error {
	if len(data) == 0 || len(data) > 64<<10 {
		return errors.New("select a PEM certificate file up to 64 KiB")
	}
	for count := 0; ; count++ {
		data = bytes.TrimSpace(data)
		if len(data) == 0 && count > 0 {
			return nil
		}
		if count >= 8 || !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return errors.New("upload certificates only, without a private key or other data")
		}
		endMarker := []byte("-----END CERTIFICATE-----")
		end := bytes.Index(data, endMarker)
		if end < 0 {
			return errors.New("invalid PEM certificate")
		}
		end += len(endMarker)
		chunk := data[:end]
		block, rest := pem.Decode(chunk)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || bytes.Count(chunk, []byte("-----BEGIN")) != 1 {
			return errors.New("invalid PEM certificate")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return errors.New("invalid X.509 certificate")
		}
		data = data[end:]
	}
}

// CleanupPushRequests removes expired encrypted key records in bounded batches.
// Database backups and WAL retain their normal operator-defined retention.
func (s *Store) CleanupPushRequests(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `WITH due AS (
	 SELECT id FROM mdm_apple_push_requests WHERE status='pending' AND expires_at<=clock_timestamp()
	 ORDER BY expires_at,id LIMIT 100 FOR UPDATE SKIP LOCKED
	), expired AS (
	 UPDATE mdm_apple_push_requests r SET status='expired',encrypted_key=NULL,completed_at=clock_timestamp()
	 FROM due WHERE r.id=due.id RETURNING r.tenant_id,r.id
	) INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id)
	 SELECT tenant_id,'system','apple.push_request.expire',id::text FROM expired`)
	return err
}
