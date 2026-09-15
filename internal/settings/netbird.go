package settings

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-uem/nats/legacysecret"
	"github.com/open-uem/nats/netbirdapi"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var (
	ErrNetbirdInvalid   = errors.New("invalid NetBird settings request")
	ErrNetbirdMissing   = errors.New("NetBird organization is unavailable")
	ErrNetbirdConflict  = errors.New("NetBird settings changed; reload before saving")
	ErrNetbirdSecret    = errors.New("NetBird secret storage is unavailable")
	ErrNetbirdMigration = errors.New("NetBird secret migration is incomplete")
)

type NetbirdReview struct {
	ID            int64
	Revision      string
	ManagementURL string
	TokenSet      bool
	Shared        bool
}

type NetbirdStore struct {
	db          *sql.DB
	permissions *access.Store
	key         string
}

func NewNetbirdStore(db *sql.DB, permissions *access.Store, key string) (*NetbirdStore, error) {
	if db == nil || permissions == nil {
		return nil, ErrNetbirdInvalid
	}
	return &NetbirdStore{db, permissions, key}, nil
}

//go:embed migrations/002_netbird.sql
var netbirdSchema embed.FS

func (s *NetbirdStore) Migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684630103); CREATE TABLE IF NOT EXISTS uem_settings_migrations(name TEXT PRIMARY KEY,applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())`); err != nil {
		return err
	}
	var installed bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_settings_migrations WHERE name='002_netbird')`).Scan(&installed); err != nil {
		return err
	}
	if !installed {
		body, err := netbirdSchema.ReadFile("migrations/002_netbird.sql")
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, string(body)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_settings_migrations(name) VALUES('002_netbird')`); err != nil {
			return err
		}
	}
	for _, table := range []string{"netbird_settings", "tenants"} {
		trigger := "uem_netbird_settings_revision"
		if table == "tenants" {
			trigger = "uem_netbird_tenant_revision"
		}
		var valid bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=$1::regclass AND tgname=$2 AND tgtype=19 AND tgenabled IN ('O','A') AND tgfoid=($2||'()')::regprocedure) AND EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid=$1::regclass AND attname='uem_netbird_revision' AND atttypid='uuid'::regtype AND attnotnull AND NOT attisdropped)`, table, trigger).Scan(&valid); err != nil {
			return err
		}
		if !valid {
			return errors.New("NetBird revision protection is unavailable")
		}
	}
	return tx.Commit()
}

func (s *NetbirdStore) begin(ctx context.Context, actor string, scope access.Scope, write bool) (*sql.Tx, string, int64, error) {
	if scope.TenantID <= 0 || scope.SiteID != 0 {
		return nil, "", 0, ErrNetbirdInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", 0, err
	}
	fail := func(err error) (*sql.Tx, string, int64, error) { tx.Rollback(); return nil, "", 0, err }
	if err = s.permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageSettings, access.Scope{}); err != nil {
		return fail(err)
	}
	lock := " FOR SHARE"
	if write {
		lock = " FOR UPDATE"
	}
	var revision string
	var id int64
	if err = tx.QueryRowContext(ctx, `SELECT uem_netbird_revision::text,coalesce(tenant_netbird,0) FROM tenants WHERE id=$1`+lock, scope.TenantID).Scan(&revision, &id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = ErrNetbirdMissing
		}
		return fail(err)
	}
	return tx, revision, id, nil
}

func netbirdRevision(link, settings string) string {
	sum := sha256.Sum256([]byte(link + ":" + settings))
	return hex.EncodeToString(sum[:])
}
func readNetbird(ctx context.Context, tx *sql.Tx, link string, id int64, write bool) (*NetbirdReview, error) {
	review := &NetbirdReview{ID: id, ManagementURL: "https://api.netbird.io"}
	version := ""
	if id > 0 {
		lock := " FOR SHARE"
		if write {
			lock = " FOR UPDATE"
		}
		var bounded bool
		err := tx.QueryRowContext(ctx, `SELECT uem_netbird_revision::text,CASE WHEN octet_length(management_url)<=2048 THEN management_url ELSE '' END,coalesce(access_token<>'',false),coalesce(octet_length(management_url),0)<=2048 FROM netbird_settings WHERE id=$1`+lock, id).Scan(&version, &review.ManagementURL, &review.TokenSet, &bounded)
		if err != nil {
			return nil, ErrNetbirdConflict
		}
		if !bounded {
			return nil, ErrNetbirdConflict
		}
		if err = tx.QueryRowContext(ctx, `SELECT count(*)>1 FROM tenants WHERE tenant_netbird=$1`, id).Scan(&review.Shared); err != nil {
			return nil, err
		}
	}
	review.Revision = netbirdRevision(link, version)
	return review, nil
}

func (s *NetbirdStore) Read(parent context.Context, actor string, scope access.Scope) (*NetbirdReview, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, link, id, err := s.begin(ctx, actor, scope, false)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	review, err := readNetbird(ctx, tx, link, id, false)
	if err != nil {
		return nil, err
	}
	if err = smtpAudit(ctx, tx, actor, scope, "settings.netbird.read", fmt.Sprint(id), "recorded"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return review, nil
}

func (s *NetbirdStore) Save(parent context.Context, actor string, scope access.Scope, id int64, revision, base, action, token string) error {
	decoded, err := hex.DecodeString(revision)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != revision || id < 0 || !netbirdapi.ValidBase(base) {
		return ErrNetbirdInvalid
	}
	switch action {
	case "keep", "clear":
		if token != "" {
			return ErrNetbirdInvalid
		}
	case "replace":
		if token == "" || strings.ContainsAny(token, "\r\n") {
			return ErrNetbirdInvalid
		}
	default:
		return ErrNetbirdInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, link, currentID, err := s.begin(ctx, actor, scope, true)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := readNetbird(ctx, tx, link, currentID, true)
	if err != nil {
		return err
	}
	if id != current.ID || revision != current.Revision {
		return ErrNetbirdConflict
	}
	if action == "replace" {
		token, err = legacysecret.Seal(token, s.key)
		if err != nil {
			return ErrNetbirdSecret
		}
	}
	if id == 0 {
		if err = tx.QueryRowContext(ctx, `INSERT INTO netbird_settings(management_url,access_token) VALUES($1,$2) RETURNING id`, base, token).Scan(&id); err != nil {
			return err
		}
	} else if current.Shared {
		// Copy only this organization's configuration; keep copies ciphertext
		// inside SQL without transferring it into the application.
		if err = tx.QueryRowContext(ctx, `INSERT INTO netbird_settings(management_url,access_token) SELECT $2,CASE WHEN $3 THEN $4 ELSE access_token END FROM netbird_settings WHERE id=$1 RETURNING id`, id, base, action != "keep", token).Scan(&id); err != nil {
			return err
		}
	} else {
		if _, err = tx.ExecContext(ctx, `UPDATE netbird_settings SET management_url=$2,access_token=CASE WHEN $3 THEN $4 ELSE access_token END WHERE id=$1`, id, base, action != "keep", token); err != nil {
			return err
		}
	}
	if id != current.ID {
		if _, err = tx.ExecContext(ctx, `UPDATE tenants SET tenant_netbird=$2 WHERE id=$1`, scope.TenantID, id); err != nil {
			return err
		}
	}
	resource := fmt.Sprintf("%d/from/%d/token/%s", id, current.ID, action)
	if err = smtpAudit(ctx, tx, actor, scope, "settings.netbird.update", resource, "success"); err != nil {
		return err
	}
	return tx.Commit()
}
