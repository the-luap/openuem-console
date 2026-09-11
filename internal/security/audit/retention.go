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
	WindowsEnabled bool
	TenantID       int
	Days           int
	Revision       int64
	UpdatedAt      *time.Time
	UpdatedBy      string
}

type RetentionEvent struct {
	WindowsEnabled         bool
	PreviousWindowsEnabled *bool
	Actor, Action, Source  string
	Days                   int
	PreviousDays           *int
	Revision               int64
	Count                  int
	CreatedAt              time.Time
	Cutoff                 *time.Time
}

type RetentionPreview struct {
	WindowsEnabled bool
	ID, Token      string
	Policy         RetentionPolicy
	Days           int
	Cutoff         *time.Time
	ExpiresAt      time.Time
	Counts         map[string]int64
}

func validDays(days int) bool { return days == 0 || (days >= 30 && days <= 3650) }

func retentionPolicy(ctx context.Context, tx *sql.Tx, tenant int, lock bool) (RetentionPolicy, error) {
	p := RetentionPolicy{TenantID: tenant}
	query := `SELECT days,revision,updated_at,updated_by,windows_enabled FROM uem_audit_retention WHERE tenant_id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	err := tx.QueryRowContext(ctx, query, tenant).Scan(&p.Days, &p.Revision, &p.UpdatedAt, &p.UpdatedBy, &p.WindowsEnabled)
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
	rows, err := tx.QueryContext(ctx, `SELECT actor,action,source,days,previous_days,revision,event_count,created_at,cutoff,windows_enabled,previous_windows_enabled FROM uem_audit_retention_history WHERE tenant_id=$1 ORDER BY created_at DESC,id DESC LIMIT 25`, scope.TenantID)
	if err != nil {
		return p, nil, err
	}
	history := []RetentionEvent{}
	for rows.Next() {
		var e RetentionEvent
		if err = rows.Scan(&e.Actor, &e.Action, &e.Source, &e.Days, &e.PreviousDays, &e.Revision, &e.Count, &e.CreatedAt, &e.Cutoff, &e.WindowsEnabled, &e.PreviousWindowsEnabled); err != nil {
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

type retentionSource struct{ name, table, predicate, query string }

func retentionSources(ctx context.Context, tx *sql.Tx, tenant int, windowsEnabled bool) ([]retentionSource, error) {
	available, err := availableSources(ctx, tx)
	if err != nil {
		return nil, err
	}
	result := []retentionSource{}
	for i, source := range sourceQueries {
		if source.name == "retention" || isWindowsSource(source.name) && !windowsEnabled {
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
		query := source.query
		if source.name == "inventory-refresh" {
			// Attempt evidence drives bounded retry and uncertainty after a
			// process/commit failure. Retain it until that request is terminal.
			eligible := `NOT EXISTS(SELECT 1 FROM uem_inventory_refresh r WHERE r.id=uem_inventory_refresh_audit.request_id AND r.status='queued')`
			predicate += ` AND ` + eligible
			query += ` WHERE ` + eligible
		}
		if global {
			predicate = `$1::bigint=0 AND created_at<$2`
		}
		result = append(result, retentionSource{name: source.name, table: source.table, predicate: predicate, query: query})
	}
	return result, nil
}

func previewTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Store) PreviewRetention(ctx context.Context, actor string, scope access.Scope, days int) (*RetentionPreview, error) {
	return s.PreviewRetentionWithWindows(ctx, actor, scope, days, false)
}

// PreviewRetentionWithWindows requires explicit inclusion of Windows audit rows;
// upgrading an existing policy never expands its deletion scope automatically.
func (s *Store) PreviewRetentionWithWindows(ctx context.Context, actor string, scope access.Scope, days int, windowsEnabled bool) (*RetentionPreview, error) {
	if scope.SiteID != 0 || !validDays(days) || windowsEnabled && scope.TenantID <= 0 {
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
	preview := &RetentionPreview{ID: uuid.NewString(), Policy: p, Days: days, WindowsEnabled: windowsEnabled, Counts: map[string]int64{}}
	if days > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -days)
		preview.Cutoff = &cutoff
	}
	sources, err := retentionSources(ctx, tx, scope.TenantID, windowsEnabled)
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		count := int64(0)
		if preview.Cutoff != nil {
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM (`+source.query+`) e WHERE tenant_id=$1 AND created_at<$2`, scope.TenantID, *preview.Cutoff).Scan(&count); err != nil {
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
	err = tx.QueryRowContext(ctx, `INSERT INTO uem_audit_retention_previews(id,token_hash,actor,tenant_id,days,revision,cutoff,counts,windows_enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING expires_at`, preview.ID, previewTokenHash(preview.Token), actor, scope.TenantID, days, p.Revision, preview.Cutoff, counts, windowsEnabled).Scan(&preview.ExpiresAt)
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
	var windowsEnabled bool
	var revision int64
	var hash string
	var cutoff *time.Time
	var expires time.Time
	err = tx.QueryRowContext(ctx, `SELECT days,revision,token_hash,cutoff,expires_at,windows_enabled FROM uem_audit_retention_previews WHERE id=$1 AND actor=$2 AND tenant_id=$3 AND expires_at>clock_timestamp() FOR UPDATE`, id, actor, scope.TenantID).Scan(&days, &revision, &hash, &cutoff, &expires, &windowsEnabled)
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_audit_retention(tenant_id,days,revision,updated_by,windows_enabled) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id) DO UPDATE SET days=EXCLUDED.days,revision=EXCLUDED.revision,updated_by=EXCLUDED.updated_by,windows_enabled=EXCLUDED.windows_enabled,updated_at=clock_timestamp(),next_sweep_at=clock_timestamp()`, scope.TenantID, days, revision+1, actor, windowsEnabled); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_audit_retention_history(tenant_id,actor,action,previous_days,days,revision,cutoff,previous_windows_enabled,windows_enabled) VALUES($1,$2,'retention.change',$3,$4,$5,$6,$7,$8)`, scope.TenantID, actor, p.Days, days, revision+1, cutoff, p.WindowsEnabled, windowsEnabled); err != nil {
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
		var windowsEnabled bool
		var revision int64
		err = tx.QueryRowContext(ctx, `SELECT tenant_id,days,revision,windows_enabled FROM uem_audit_retention WHERE days>0 AND next_sweep_at<=clock_timestamp() ORDER BY next_sweep_at,tenant_id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&tenant, &days, &revision, &windowsEnabled)
		if errors.Is(err, sql.ErrNoRows) {
			tx.Rollback()
			return nil
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		sources, err := retentionSources(ctx, tx, tenant, windowsEnabled)
		if err != nil {
			tx.Rollback()
			return err
		}
		var cutoff time.Time
		if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()-$1::integer*interval '1 day'`, days).Scan(&cutoff); err != nil {
			tx.Rollback()
			return err
		}
		more := false
		for _, source := range sources {
			var count int
			if isWindowsSource(source.name) {
				count, err = pruneWindowsAudit(ctx, tx, RetentionPolicy{TenantID: tenant, Days: days, Revision: revision, WindowsEnabled: windowsEnabled}, source, cutoff)
			} else {
				query := fmt.Sprintf(`WITH selected AS (SELECT id FROM %s WHERE %s ORDER BY created_at,id LIMIT 1000 FOR UPDATE SKIP LOCKED), deleted AS (DELETE FROM %s WHERE id IN (SELECT id FROM selected) RETURNING id) SELECT count(*) FROM deleted`, source.table, source.predicate, source.table)
				err = tx.QueryRowContext(ctx, query, tenant, cutoff).Scan(&count)
			}
			if err != nil {
				break
			}
			if count == 1000 {
				more = true
			}
			if count > 0 && !isWindowsSource(source.name) {
				_, err = tx.ExecContext(ctx, `INSERT INTO uem_audit_retention_history(tenant_id,actor,action,days,revision,source,cutoff,event_count,windows_enabled) VALUES($1,'retention-service','retention.prune',$2,$3,$4,$5,$6,$7)`, tenant, days, revision, source.name, cutoff, count, windowsEnabled)
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
