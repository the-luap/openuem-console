package settings

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/legacysecret"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrRecent = errors.New("an SMTP test was attempted recently")

type SMTPTestResult struct {
	ID        string
	Status    string
	Revision  string
	CreatedAt time.Time
}

// SMTPTestSender sends exactly one message to cfg.From and honors cancellation.
// It must never log or persist configuration, credentials or provider errors.
type SMTPTestSender func(context.Context, SMTPConfig, string) error

// Test uses saved configuration only. A committed independent attempt prevents
// replay after a timeout, lost response or terminal audit/database failure.
func (s *SMTPStore) Test(parent context.Context, actor string, scope access.Scope, id int64, revision, attemptID string, send SMTPTestSender) (*SMTPTestResult, error) {
	request, err := uuid.Parse(attemptID)
	if err != nil || request.String() != attemptID || request.Version() != 4 || id <= 0 || send == nil || s.db.Stats().MaxOpenConnections == 1 {
		return nil, ErrInvalid
	}
	source, err := uuid.Parse(revision)
	if err != nil || source.String() != revision {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,684630102))`, attemptID); err != nil {
		return nil, err
	}
	var savedActor, savedRevision, status string
	var savedID int64
	var savedTenant int
	var createdAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT actor,settings_id,tenant_id,revision::text,status,created_at FROM uem_smtp_test_attempts WHERE id=$1`, attemptID).Scan(&savedActor, &savedID, &savedTenant, &savedRevision, &status, &createdAt)
	if err == nil {
		if savedActor != actor || savedID != id || savedTenant != scope.TenantID || savedRevision != revision {
			return nil, ErrConflict
		}
		// Replay returns the original outcome without requiring unchanged settings.
		// It never reads the old secret or claims an attempted message was delivered.
		if status == "attempted" {
			status = "unconfirmed"
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return &SMTPTestResult{ID: attemptID, Status: status, Revision: revision, CreatedAt: createdAt}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	current, err := readSMTP(ctx, tx, scope, true)
	if err != nil {
		return nil, err
	}
	if current.ID != id {
		return nil, ErrNotFound
	}
	if current.Revision != revision {
		return nil, ErrConflict
	}
	if !current.Config.Valid() {
		return nil, ErrInvalid
	}
	var recent bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_smtp_test_attempts WHERE settings_id=$1 AND created_at>clock_timestamp()-interval '1 minute')`, id).Scan(&recent); err != nil {
		return nil, err
	}
	if recent {
		return nil, ErrRecent
	}
	var stored string
	if err = tx.QueryRowContext(ctx, `SELECT coalesce(smtp_password,'') FROM settings WHERE id=$1 AND coalesce(octet_length(smtp_password),0)<=$2`, id, legacysecret.MaxStoredSize).Scan(&stored); err != nil {
		return nil, ErrSecret
	}
	password, err := legacysecret.Open(stored, s.key)
	if err != nil {
		return nil, ErrSecret
	}
	evidence, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer evidence.Rollback()
	if err = evidence.QueryRowContext(ctx, `INSERT INTO uem_smtp_test_attempts(id,settings_id,tenant_id,revision,actor) VALUES($1,$2,$3,$4,$5) RETURNING created_at`, attemptID, id, scope.TenantID, revision, actor).Scan(&createdAt); err != nil {
		return nil, err
	}

	resource := fmt.Sprintf("%d/test/%s", id, attemptID)
	if err = smtpAudit(ctx, evidence, actor, scope, "settings.smtp.test_attempt", resource, "recorded"); err != nil {
		return nil, err
	}
	if err = evidence.Commit(); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	status = "sent"
	sendCtx, stop := context.WithTimeout(ctx, 15*time.Second)
	sendErr := send(sendCtx, current.Config, password)
	stop()
	action, result := "settings.smtp.test_sent", "success"
	if sendErr != nil {
		status, action, result = "unconfirmed", "settings.smtp.test_unconfirmed", "failure"
	}
	if _, err = tx.ExecContext(ctx, `UPDATE uem_smtp_test_attempts SET status=$2,finished_at=clock_timestamp() WHERE id=$1 AND status='attempted'`, attemptID, status); err != nil {
		return nil, err
	}
	if err = smtpAudit(ctx, tx, actor, scope, action, resource, result); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &SMTPTestResult{ID: attemptID, Status: status, Revision: revision, CreatedAt: createdAt}, nil
}
