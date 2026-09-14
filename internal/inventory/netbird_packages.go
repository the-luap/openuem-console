package inventory

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var (
	ErrNetbirdPackageInvalid  = errors.New("invalid NetBird package approval")
	ErrNetbirdPackageMissing  = errors.New("NetBird package approval is unavailable in this organization")
	ErrNetbirdPackageConflict = errors.New("NetBird package approval no longer matches the reviewed request")
	ErrNetbirdPackageSecret   = errors.New("NetBird package source storage is unavailable")
)

// NetbirdPackageApproval deliberately has no source URL or encrypted envelope.
// Read-only software roles can inspect the immutable approval and its revocation.
type NetbirdPackageApproval struct {
	ID, Actor, Platform, Architecture, Format, PackageID, Version string
	SHA256, Digest, Verification                                  string
	TenantID, Size                                                int64
	CreatedAt                                                     time.Time
	RevocationID, RevokedBy                                       string
	RevokedAt                                                     *time.Time
}

type NetbirdPackagePage struct {
	Approvals []NetbirdPackageApproval
	Next      string
}

type NetbirdPackageStore struct {
	db          *sql.DB
	permissions *access.Store
	master      string
}

func NewNetbirdPackageStore(db *sql.DB, permissions *access.Store, master string) (*NetbirdPackageStore, error) {
	if db == nil || permissions == nil {
		return nil, ErrNetbirdPackageInvalid
	}
	return &NetbirdPackageStore{db, permissions, master}, nil
}

func (s *NetbirdPackageStore) begin(ctx context.Context, actor string, scope access.Scope, capability access.Capability) (*sql.Tx, error) {
	if scope.TenantID <= 0 || scope.SiteID != 0 {
		return nil, ErrNetbirdPackageInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if err = s.permissions.AuthorizeTransaction(ctx, tx, actor, capability, scope); err != nil {
		tx.Rollback()
		return nil, err
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, `SELECT true FROM tenants WHERE id=$1 FOR SHARE`, scope.TenantID).Scan(&exists); err != nil {
		tx.Rollback()
		if errors.Is(err, sql.ErrNoRows) {
			err = ErrNetbirdPackageMissing
		}
		return nil, err
	}
	return tx, nil
}

func packageAudit(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope, action, resource string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO uem_settings_audit(tenant_id,site_id,actor,action,resource_id,result) VALUES($1,0,$2,$3,$4,'success')`, scope.TenantID, actor, "settings.netbird.packages."+action, resource)
	return err
}

const netbirdPackageColumns = `p.id::text,p.tenant_id,p.actor,p.platform,p.architecture,p.format,p.package_id,p.version,p.size,p.sha256,p.digest,p.verification,p.created_at,coalesce(r.id::text,''),coalesce(r.actor,''),r.created_at`
const netbirdPackageFrom = ` FROM uem_netbird_packages p LEFT JOIN uem_netbird_package_revocations r ON r.approval_id=p.id `

func scanNetbirdPackage(row interface{ Scan(...any) error }) (*NetbirdPackageApproval, error) {
	var p NetbirdPackageApproval
	err := row.Scan(&p.ID, &p.TenantID, &p.Actor, &p.Platform, &p.Architecture, &p.Format, &p.PackageID, &p.Version, &p.Size, &p.SHA256, &p.Digest, &p.Verification, &p.CreatedAt, &p.RevocationID, &p.RevokedBy, &p.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNetbirdPackageMissing
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *NetbirdPackageStore) Read(parent context.Context, actor string, scope access.Scope, id string) (*NetbirdPackageApproval, error) {
	if !canonicalRequestID(id) {
		return nil, ErrNetbirdPackageInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.ReadSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	p, err := scanNetbirdPackage(tx.QueryRowContext(ctx, `SELECT `+netbirdPackageColumns+netbirdPackageFrom+`WHERE p.tenant_id=$1 AND p.id=$2`, scope.TenantID, id))
	if err != nil {
		return nil, err
	}
	if err = packageAudit(ctx, tx, actor, scope, "read", id); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}

// List uses an immutable approval ID cursor constrained to this organization.
// New approvals cannot displace records from later pages of an existing history.
func (s *NetbirdPackageStore) List(parent context.Context, actor string, scope access.Scope, after string) (*NetbirdPackagePage, error) {
	if after != "" && !canonicalRequestID(after) {
		return nil, ErrNetbirdPackageInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.ReadSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var cursorAt time.Time
	if after != "" {
		if err = tx.QueryRowContext(ctx, `SELECT created_at FROM uem_netbird_packages WHERE tenant_id=$1 AND id=$2`, scope.TenantID, after).Scan(&cursorAt); err != nil {
			return nil, ErrNetbirdPackageMissing
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+netbirdPackageColumns+netbirdPackageFrom+`WHERE p.tenant_id=$1 AND ($2='' OR (p.created_at,p.id)<($3,NULLIF($2,'')::uuid)) ORDER BY p.created_at DESC,p.id DESC LIMIT 51`, scope.TenantID, after, cursorAt)
	if err != nil {
		return nil, err
	}
	page := &NetbirdPackagePage{Approvals: []NetbirdPackageApproval{}}
	for rows.Next() {
		p, err := scanNetbirdPackage(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		page.Approvals = append(page.Approvals, *p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(page.Approvals) > 50 {
		page.Approvals = page.Approvals[:50]
		page.Next = page.Approvals[49].ID
	}
	if err = packageAudit(ctx, tx, actor, scope, "list", "packages"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}

func validPackageVerification(value string) bool {
	return len(value) > 0 && len(value) <= 512 && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

// Approve commits exact intent and audit atomically. Reusing an approval UUID
// must match the original actor, complete descriptor and verification reference.
// Approval never downloads bytes, contacts a provider or dispatches a command.
func (s *NetbirdPackageStore) Approve(parent context.Context, actor string, scope access.Scope, p packageapi.Package, verification string) (*NetbirdPackageApproval, error) {
	data, err := packageapi.Encode(p)
	if err != nil || p.TenantID != int64(scope.TenantID) || !validPackageVerification(verification) {
		return nil, ErrNetbirdPackageInvalid
	}
	defer clear(data)
	digest, err := p.Digest()
	if err != nil {
		return nil, ErrNetbirdPackageInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.ManageSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "netbird-package:"+p.ApprovalID); err != nil {
		return nil, err
	}
	current, err := scanNetbirdPackage(tx.QueryRowContext(ctx, `SELECT `+netbirdPackageColumns+netbirdPackageFrom+`WHERE p.id=$1 FOR UPDATE OF p`, p.ApprovalID))
	if err == nil {
		if current.TenantID != p.TenantID || current.Actor != actor || current.Digest != digest || current.Verification != verification {
			return nil, ErrNetbirdPackageConflict
		}
		var encrypted []byte
		if err = tx.QueryRowContext(ctx, `SELECT encrypted_descriptor FROM uem_netbird_packages WHERE id=$1`, p.ApprovalID).Scan(&encrypted); err != nil {
			return nil, err
		}
		plain, err := s.openPackage(current, encrypted)
		defer clear(plain)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(plain, data) {
			return nil, ErrNetbirdPackageConflict
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return current, nil
	}
	if !errors.Is(err, ErrNetbirdPackageMissing) {
		return nil, err
	}
	current = &NetbirdPackageApproval{ID: p.ApprovalID, TenantID: p.TenantID, Actor: actor, Platform: p.Platform, Architecture: p.Architecture, Format: p.Format, PackageID: p.PackageID, Version: p.Version, Size: p.Size, SHA256: p.SHA256, Digest: digest, Verification: verification}
	encrypted, err := s.sealPackage(current, data)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_packages(id,tenant_id,actor,platform,architecture,format,package_id,version,size,sha256,digest,verification,encrypted_descriptor) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, current.ID, current.TenantID, current.Actor, current.Platform, current.Architecture, current.Format, current.PackageID, current.Version, current.Size, current.SHA256, current.Digest, current.Verification, encrypted)
	if err != nil {
		return nil, err
	}
	if err = packageAudit(ctx, tx, actor, scope, "approve", current.ID); err != nil {
		return nil, err
	}
	current, err = scanNetbirdPackage(tx.QueryRowContext(ctx, `SELECT `+netbirdPackageColumns+netbirdPackageFrom+`WHERE p.id=$1`, current.ID))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return current, nil
}

// Revoke appends permanent denial of future admission. It does not cancel an
// already admitted operation or uninstall software. The reviewed descriptor
// digest and original request UUID remain necessary for an exact replay.
func (s *NetbirdPackageStore) Revoke(parent context.Context, actor string, scope access.Scope, id, digest, requestID string) (*NetbirdPackageApproval, error) {
	if !canonicalRequestID(id) || !canonicalRequestID(requestID) || len(digest) != 64 {
		return nil, ErrNetbirdPackageInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.ManageSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Acquire the row lock in a separate statement. A joined revocation read
	// started before a competing transaction commits could retain its old
	// snapshot even after waiting for the unchanged approval row's lock.
	var locked string
	if err = tx.QueryRowContext(ctx, `SELECT id::text FROM uem_netbird_packages WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, scope.TenantID, id).Scan(&locked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = ErrNetbirdPackageMissing
		}
		return nil, err
	}
	p, err := scanNetbirdPackage(tx.QueryRowContext(ctx, `SELECT `+netbirdPackageColumns+netbirdPackageFrom+`WHERE p.tenant_id=$1 AND p.id=$2`, scope.TenantID, id))
	if err != nil {
		return nil, err
	}
	if p.Digest != digest {
		return nil, ErrNetbirdPackageConflict
	}
	if p.RevokedAt != nil {
		if p.RevokedBy != actor || p.RevocationID != requestID {
			return nil, ErrNetbirdPackageConflict
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return p, nil
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_package_revocations(approval_id,id,actor,digest) VALUES($1,$2,$3,$4)`, id, requestID, actor, digest)
	if err != nil {
		var state interface{ SQLState() string }
		if errors.As(err, &state) && state.SQLState() == "23505" {
			return nil, ErrNetbirdPackageConflict
		}
		return nil, err
	}
	if err = packageAudit(ctx, tx, actor, scope, "revoke", id+"/"+requestID); err != nil {
		return nil, err
	}
	p, err = scanNetbirdPackage(tx.QueryRowContext(ctx, `SELECT `+netbirdPackageColumns+netbirdPackageFrom+`WHERE p.id=$1`, id))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}

const netbirdPackagePurpose = "openuem:netbird-package-approval:v1:"

func (s *NetbirdPackageStore) packageCipher() (cipher.AEAD, error) {
	if len(s.master) != 32 {
		return nil, ErrNetbirdPackageSecret
	}
	key, err := hkdf.Key(sha256.New, []byte(s.master), nil, netbirdPackagePurpose, 32)
	if err != nil {
		return nil, ErrNetbirdPackageSecret
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrNetbirdPackageSecret
	}
	return cipher.NewGCM(block)
}

func packageAAD(p *NetbirdPackageApproval) []byte {
	data, _ := json.Marshal([]string{netbirdPackagePurpose, p.ID, strconv.FormatInt(p.TenantID, 10), p.Actor, p.Digest, p.Verification})
	return data
}

func (s *NetbirdPackageStore) sealPackage(p *NetbirdPackageApproval, data []byte) ([]byte, error) {
	aead, err := s.packageCipher()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, ErrNetbirdPackageSecret
	}
	return aead.Seal(nonce, nonce, data, packageAAD(p)), nil
}

func (s *NetbirdPackageStore) openPackage(p *NetbirdPackageApproval, data []byte) ([]byte, error) {
	aead, err := s.packageCipher()
	if err != nil {
		return nil, err
	}
	if len(data) <= aead.NonceSize()+aead.Overhead() || len(data) > packageapi.MaxMessage+aead.NonceSize()+aead.Overhead() {
		return nil, ErrNetbirdPackageSecret
	}
	plain, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], packageAAD(p))
	if err != nil {
		return nil, ErrNetbirdPackageSecret
	}
	return plain, nil
}
