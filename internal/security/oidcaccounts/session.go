package oidcaccounts

import (
	"context"
	"database/sql"
	"errors"

	"github.com/open-uem/nats"
)

// Session contains local admission evidence, never provider access or ID tokens.
// Any binding revision change requires a fresh OpenID sign-in for this account.
type Session struct {
	UserID, Subject string
	Policy          Policy
	Revision        int64
}

func (s *Store) SessionFor(ctx context.Context, p Policy, uid, subject string) (*Session, error) {
	return s.inspectSession(ctx, Session{UserID: uid, Subject: subject, Policy: p}, false)
}

func (s *Store) ValidateSession(ctx context.Context, session Session) error {
	if session.Revision <= 0 {
		return ErrIdentity
	}
	_, err := s.inspectSession(ctx, session, true)
	return err
}

func (s *Store) inspectSession(ctx context.Context, session Session, checkRevision bool) (*Session, error) {
	if session.UserID == "" || !validIdentity(session.Policy.Issuer, session.Subject) {
		return nil, ErrIdentity
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	policy, err := readPolicy(ctx, tx)
	if err != nil {
		return nil, err
	}
	if !policy.Enabled || policy != session.Policy {
		return nil, ErrIdentity
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock_shared(684627916)`); err != nil {
		return nil, err
	}
	var revision int64
	var eligible bool
	var status string
	err = tx.QueryRowContext(ctx, `SELECT a.revision,b.active AND COALESCE(u.openid,false) AND NOT COALESCE(u.passwd,false) AND u.register<>$4,u.register FROM uem_oidc_bindings b JOIN uem_oidc_accounts a ON a.user_id=b.user_id JOIN users u ON u.uid=a.user_id WHERE b.issuer=$1 AND b.subject=$2 AND b.user_id=$3 FOR SHARE OF u`, policy.Issuer, session.Subject, session.UserID, nats.REGISTER_REVOKED).Scan(&revision, &eligible, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIdentity
	}
	if err != nil {
		return nil, err
	}
	if !eligible || (checkRevision && revision != session.Revision) {
		return nil, ErrIdentity
	}
	if status != nats.REGISTER_APPROVED && status != nats.REGISTER_COMPLETE && (checkRevision || !policy.AutoApprove) {
		return nil, ErrIdentity
	}
	session.Revision = revision
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &session, nil
}
