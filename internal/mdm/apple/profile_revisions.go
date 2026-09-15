package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"howett.net/plist"
)

var ErrProfileRevision = errors.New("invalid profile revision request")

// Revision metadata is safe for catalog readers. Payloads have a separate,
// permission-protected download path and never enter this page model.
type ProfileRevision struct {
	ID, ProfileID, Name, Identifier, UUID, Scope string
	Actor, Reason, Origin, RestoredFrom          string
	Revision, CurrentRevision                    int
	PayloadTypes                                 []string
	CreatedAt                                    time.Time
}

func profileRevisionUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func (s *Store) appendProfileRevision(ctx context.Context, tx *sql.Tx, p *Profile, actor, restoredFrom, reason string) (string, error) {
	if actor == "" {
		return "", ErrProfileRevision
	}
	id := uuid.NewString()
	encrypted, err := s.secrets.seal(p.Payload, secretPurpose(p.TenantID, id, "profile_revision"))
	if err != nil {
		return "", err
	}
	types, err := json.Marshal(p.PayloadTypes)
	if err != nil {
		return "", err
	}
	origin := "save"
	var source any
	if restoredFrom != "" {
		origin = "restore"
		source = restoredFrom
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_profile_revisions(id,tenant_id,profile_id,revision,name,identifier,payload_uuid,payload_scope,payload_types,encrypted_payload,encryption_kind,origin,actor,reason,restored_from) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'revision',$11,$12,$13,$14)`, id, p.TenantID, p.ID, p.Revision, p.Name, p.Identifier, p.UUID, p.Scope, types, encrypted, origin, actor, reason, source)
	return id, err
}

const profileRevisionColumns = `r.id,r.profile_id,r.revision,r.name,r.identifier,r.payload_uuid,r.payload_scope,r.payload_types,r.actor,r.reason,r.origin,COALESCE(r.restored_from::text,''),r.created_at,COALESCE(p.revision,0)`
const profileRevisionFrom = ` FROM mdm_apple_profile_revisions r LEFT JOIN mdm_apple_profiles p ON p.tenant_id=r.tenant_id AND p.id=r.profile_id `

func scanProfileRevision(row scanner) (ProfileRevision, error) {
	var v ProfileRevision
	var types []byte
	err := row.Scan(&v.ID, &v.ProfileID, &v.Revision, &v.Name, &v.Identifier, &v.UUID, &v.Scope, &types, &v.Actor, &v.Reason, &v.Origin, &v.RestoredFrom, &v.CreatedAt, &v.CurrentRevision)
	if err != nil {
		return v, notFound(err)
	}
	err = json.Unmarshal(types, &v.PayloadTypes)
	return v, err
}

// An empty profile selects the organization's history, including deleted
// catalog entries. A filtered page remains addressable after catalog deletion.
func (s *Store) ProfileRevisions(ctx context.Context, tenant int, profile, before string) ([]ProfileRevision, string, error) {
	if tenant <= 0 || profile != "" && !profileRevisionUUID(profile) || before != "" && !profileRevisionUUID(before) {
		return nil, "", ErrProfileRevision
	}
	var family, stamp, cursor any
	if profile != "" {
		family = profile
	}
	if before != "" {
		var at time.Time
		if err := s.db.QueryRowContext(ctx, `SELECT created_at FROM mdm_apple_profile_revisions WHERE tenant_id=$1 AND id=$2 AND ($3::uuid IS NULL OR profile_id=$3)`, tenant, before, family).Scan(&at); err != nil {
			return nil, "", notFound(err)
		}
		stamp, cursor = at, before
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+profileRevisionColumns+profileRevisionFrom+`WHERE r.tenant_id=$1 AND ($2::uuid IS NULL OR r.profile_id=$2) AND ($3::timestamptz IS NULL OR (r.created_at,r.id)<($3,$4::uuid)) ORDER BY r.created_at DESC,r.id DESC LIMIT 101`, tenant, family, stamp, cursor)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := []ProfileRevision{}
	for rows.Next() {
		v, err := scanProfileRevision(rows)
		if err != nil {
			return nil, "", err
		}
		items = append(items, v)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	if profile != "" && before == "" && len(items) == 0 {
		return nil, "", ErrNotFound
	}
	next := ""
	if len(items) > 100 {
		items = items[:100]
		next = items[99].ID
	}
	return items, next, nil
}

type profileRevisionReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) profileRevisionPayload(ctx context.Context, q profileRevisionReader, tenant int, id string) (*Profile, error) {
	var p Profile
	var types, encrypted []byte
	var encryptionKind string
	err := q.QueryRowContext(ctx, `SELECT profile_id,tenant_id,name,identifier,payload_uuid,revision,payload_types,encrypted_payload,created_at,payload_scope,encryption_kind FROM mdm_apple_profile_revisions WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&p.ID, &p.TenantID, &p.Name, &p.Identifier, &p.UUID, &p.Revision, &types, &encrypted, &p.UpdatedAt, &p.Scope, &encryptionKind)
	if err != nil {
		return nil, notFound(err)
	}
	if err = json.Unmarshal(types, &p.PayloadTypes); err != nil {
		return nil, err
	}
	purpose := secretPurpose(tenant, id, "profile_revision")
	if encryptionKind == "profile" {
		purpose = secretPurpose(tenant, p.ID, "profile")
	} else if encryptionKind != "revision" {
		return nil, ErrProfileRevision
	}
	p.Payload, err = s.secrets.open(encrypted, purpose)
	if err != nil {
		return nil, err
	}
	// Legacy snapshots retain the original profile-bound envelope. Its root
	// UUID and identity must match this historical row before it can be used.
	var root map[string]any
	if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
		return nil, ErrProfileRevision
	}
	scope := stringValue(root, "PayloadScope")
	if _, exists := root["PayloadScope"]; !exists {
		scope = "System"
	}
	if stringValue(root, "PayloadUUID") != p.UUID || stringValue(root, "PayloadIdentifier") != p.Identifier || scope != p.Scope {
		return nil, ErrProfileRevision
	}
	return &p, nil
}

func (s *Store) ProfileRevisionPayload(ctx context.Context, tenant int, id string) (*Profile, error) {
	if tenant <= 0 || !profileRevisionUUID(id) {
		return nil, ErrProfileRevision
	}
	return s.profileRevisionPayload(ctx, s.db, tenant, id)
}

func (s *Store) RestoreProfileRevision(ctx context.Context, tenant int, profile, revision string, expected int, reason, actor string, permissions *access.Store) (*Profile, error) {
	return s.restoreProfileRevision(ctx, tenant, profile, revision, expected, reason, actor, func(ctx context.Context, tx *sql.Tx) error {
		if permissions == nil {
			return access.ErrDenied
		}
		for _, capability := range []access.Capability{access.ManageProfiles, access.AssignProfiles} {
			if err := permissions.AuthorizeTransaction(ctx, tx, actor, capability, access.Scope{TenantID: tenant}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) restoreProfileRevision(ctx context.Context, tenant int, profile, revision string, expected int, reason, actor string, authorize func(context.Context, *sql.Tx) error) (*Profile, error) {
	reason = strings.TrimSpace(reason)
	if tenant <= 0 || !profileRevisionUUID(profile) || !profileRevisionUUID(revision) || expected <= 0 || expected >= 2147483647 || !validMacAppText(reason, 1000) || actor == "" {
		return nil, ErrProfileRevision
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if authorize != nil {
		if err = authorize(ctx, tx); err != nil {
			return nil, err
		}
	}
	current, err := s.scanProfile(tx.QueryRowContext(ctx, `SELECT `+profileColumns+` FROM mdm_apple_profiles WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, profile))
	if err != nil {
		return nil, err
	}
	if current.Revision != expected {
		return nil, ErrConflict
	}
	source, err := s.profileRevisionPayload(ctx, tx, tenant, revision)
	if err != nil {
		return nil, err
	}
	if source.ID != profile {
		return nil, ErrNotFound
	}
	if source.Revision >= current.Revision {
		return nil, ErrConflict
	}
	p, err := ParseProfile(source.Payload)
	if err != nil {
		return nil, err
	}
	if p.Identifier != current.Identifier || p.Scope != current.Scope {
		return nil, ErrProfileRevision
	}
	p.TenantID, p.ID, p.Revision = tenant, profile, current.Revision+1
	if err = s.saveProfileRevisionTx(ctx, tx, p, true, actor, revision, reason); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}
