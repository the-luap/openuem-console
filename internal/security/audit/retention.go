package audit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type RetentionPolicy struct {
	TenantID  int
	Days      int
	Revision  int64
	UpdatedAt *time.Time
	UpdatedBy string
}

type RetentionEvent struct {
	Actor, Action, Source string
	Days                  int
	PreviousDays          *int
	Revision              int64
	Count                 int
	CreatedAt             time.Time
	Cutoff                *time.Time
}

type RetentionPreview struct {
	ID, Token string
	Policy    RetentionPolicy
	Days      int
	Cutoff    *time.Time
	ExpiresAt time.Time
	Counts    map[string]int64
}

func validDays(days int) bool { return days == 0 || (days >= 30 && days <= 3650) }

func retentionPolicy(ctx context.Context, tx *sql.Tx, tenant int, lock bool) (RetentionPolicy, error) {
	p := RetentionPolicy{TenantID: tenant}
	query := `SELECT days,revision,updated_at,updated_by FROM uem_audit_retention WHERE tenant_id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	err := tx.QueryRowContext(ctx, query, tenant).Scan(&p.Days, &p.Revision, &p.UpdatedAt, &p.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	}
	return p, err
}

func (s *Store) Retention(ctx context.Context, actor string, scope access.Scope) (RetentionPolicy, []RetentionEvent, error) {
	if scope.SiteID != 0 {
		return RetentionPolicy{}, nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RetentionPolicy{}, nil, err
	}
	defer tx.Rollback()
	if err = s.authorize(ctx, tx, actor, scope); err != nil {
		return RetentionPolicy{}, nil, err
	}
	p, err := retentionPolicy(ctx, tx, scope.TenantID, false)
	if err != nil {
		return p, nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT actor,action,source,days,previous_days,revision,event_count,created_at,cutoff FROM uem_audit_retention_history WHERE tenant_id=$1 ORDER BY created_at DESC,id DESC LIMIT 25`, scope.TenantID)
	if err != nil {
		return p, nil, err
	}
	history := []RetentionEvent{}
	for rows.Next() {
		var e RetentionEvent
		if err = rows.Scan(&e.Actor, &e.Action, &e.Source, &e.Days, &e.PreviousDays, &e.Revision, &e.Count, &e.CreatedAt, &e.Cutoff); err != nil {
			rows.Close()
			return p, nil, err
		}
		history = append(history, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return p, nil, err
	}
	if err = tx.Commit(); err != nil {
		return p, nil, err
	}
	return p, history, nil
}

type retentionSource struct{ name, table, predicate string }

func retentionSources(ctx context.Context, tx *sql.Tx, tenant int) ([]retentionSource, error) {
	available, err := availableSources(ctx, tx)
	if err != nil {
		return nil, err
	}
	result := []retentionSource{}
	for i, source := range sourceQueries {
		if source.name == "retention" {
			continue
		}
		if !available[i] {
			continue
		}
		global := source.name == "access" || source.name == "release"
		if (global && tenant != 0) || (!global && source.name != "activity" && tenant == 0) {
			continue
		}
		predicate := `tenant_id=$1 AND created_at<$2`
		if global {
			predicate = `$1::bigint=0 AND created_at<$2`
		}
		result = append(result, retentionSource{name: source.name, table: source.table, predicate: predicate})
	}
	return result, nil
}

func previewTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Store) PreviewRetention(ctx context.Context, actor string, scope access.Scope, days int) (*RetentionPreview, error) {
	if scope.SiteID != 0 || !validDays(days) {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.authorizeScope(ctx, tx, actor, scope, access.ManageAuditRetention); err != nil {
		return nil, err
	}
	p, err := retentionPolicy(ctx, tx, scope.TenantID, false)
	if err != nil {
		return nil, err
	}
	preview := &RetentionPreview{ID: uuid.NewString(), Policy: p, Days: days, Counts: map[string]int64{}}
	if days > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -days)
		preview.Cutoff = &cutoff
	}
	sources, err := retentionSources(ctx, tx, scope.TenantID)
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		count := int64(0)
		if preview.Cutoff != nil {
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM `+source.table+` WHERE `+source.predicate, scope.TenantID, *preview.Cutoff).Scan(&count); err != nil {
				return nil, err
			}
		}
		preview.Counts[source.name] = count
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		return nil, err
	}
	preview.Token = base64.RawURLEncoding.EncodeToString(secret[:])
	counts, err := json.Marshal(preview.Counts)
	if err != nil {
		return nil, err
	}
	// Bound live confirmation records per account and organization. Replacing
	// earlier previews makes the most recently reviewed change authoritative.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684628902,$1::integer)`, scope.TenantID); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM uem_audit_retention_previews WHERE actor=$1 AND tenant_id=$2`, actor, scope.TenantID); err != nil {
		return nil, err
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO uem_audit_retention_previews(id,token_hash,actor,tenant_id,days,revision,cutoff,counts) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING expires_at`, preview.ID, previewTokenHash(preview.Token), actor, scope.TenantID, days, p.Revision, preview.Cutoff, counts).Scan(&preview.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return preview, nil
}

func (s *Store) ApplyRetention(ctx context.Context, actor string, scope access.Scope, id, token string) error {
	parsed, err := uuid.Parse(id)
	if scope.SiteID != 0 || err != nil || parsed.String() != id || len(token) != 43 {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.authorizeScope(ctx, tx, actor, scope, access.ManageAuditRetention); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684628902,$1::integer)`, scope.TenantID); err != nil {
		return err
	}
	var days int
	var revision int64
	var hash string
	var cutoff *time.Time
	var expires time.Time
	err = tx.QueryRowContext(ctx, `SELECT days,revision,token_hash,cutoff,expires_at FROM uem_audit_retention_previews WHERE id=$1 AND actor=$2 AND tenant_id=$3 AND expires_at>clock_timestamp() FOR UPDATE`, id, actor, scope.TenantID).Scan(&days, &revision, &hash, &cutoff, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(hash), []byte(previewTokenHash(token))) {
		return ErrConflict
	}
	p, err := retentionPolicy(ctx, tx, scope.TenantID, true)
	if err != nil {
		return err
	}
	if p.Revision != revision {
		return ErrConflict
	}
	// A concurrent sweep can hold the policy row while the preview expires.
	var live bool
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()<$1`, expires).Scan(&live); err != nil {
		return err
	}
	if !live {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_audit_retention(tenant_id,days,revision,updated_by) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id) DO UPDATE SET days=EXCLUDED.days,revision=EXCLUDED.revision,updated_by=EXCLUDED.updated_by,updated_at=clock_timestamp(),next_sweep_at=clock_timestamp()`, scope.TenantID, days, revision+1, actor); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_audit_retention_history(tenant_id,actor,action,previous_days,days,revision,cutoff) VALUES($1,$2,'retention.change',$3,$4,$5,$6)`, scope.TenantID, actor, p.Days, days, revision+1, cutoff); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM uem_audit_retention_previews WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// PruneRetention deletes only records covered by an explicitly confirmed policy.
// Each policy and all its bounded source deletions share one transaction.
func (s *Store) PruneRetention(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM uem_audit_retention_previews WHERE id IN (SELECT id FROM uem_audit_retention_previews WHERE expires_at<clock_timestamp() ORDER BY expires_at LIMIT 500)`); err != nil {
		return err
	}
	for range 10 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		var tenant, days int
		var revision int64
		err = tx.QueryRowContext(ctx, `SELECT tenant_id,days,revision FROM uem_audit_retention WHERE days>0 AND next_sweep_at<=clock_timestamp() ORDER BY next_sweep_at,tenant_id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&tenant, &days, &revision)
		if errors.Is(err, sql.ErrNoRows) {
			tx.Rollback()
			return nil
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		sources, err := retentionSources(ctx, tx, tenant)
		if err != nil {
			tx.Rollback()
			return err
		}
		cutoff := time.Now().UTC().AddDate(0, 0, -days)
		more := false
		for _, source := range sources {
			var count int
			query := fmt.Sprintf(`WITH selected AS (SELECT id FROM %s WHERE %s ORDER BY created_at,id LIMIT 1000 FOR UPDATE SKIP LOCKED), deleted AS (DELETE FROM %s WHERE id IN (SELECT id FROM selected) RETURNING id) SELECT count(*) FROM deleted`, source.table, source.predicate, source.table)
			if err = tx.QueryRowContext(ctx, query, tenant, cutoff).Scan(&count); err != nil {
				break
			}
			if count == 1000 {
				more = true
			}
			if count > 0 {
				_, err = tx.ExecContext(ctx, `INSERT INTO uem_audit_retention_history(tenant_id,actor,action,days,revision,source,cutoff,event_count) VALUES($1,'retention-service','retention.prune',$2,$3,$4,$5,$6)`, tenant, days, revision, source.name, cutoff, count)
				if err != nil {
					break
				}
			}
		}
		if err == nil {
			delay := time.Hour
			if more {
				delay = time.Minute
			}
			_, err = tx.ExecContext(ctx, `UPDATE uem_audit_retention SET next_sweep_at=$2 WHERE tenant_id=$1`, tenant, time.Now().Add(delay))
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
