package oidcaccounts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-uem/ent"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/security/mfaadmission"
)

// AdmitSession confirms a verified OpenID account only while its exact identity,
// policy and MFA state still authorize the pending or completed session. The
// caller publishes a cookie only after this transaction succeeds.
func (s *Store) AdmitSession(parent context.Context, identity Session, expected *ent.User, evidence *mfaadmission.Evidence) error {
	secondFactor := evidence != nil
	if expected == nil || expected.ID == "" || !expected.Openid || expected.Passwd || identity.UserID != expected.ID || identity.Revision <= 0 || !validIdentity(identity.Policy.Issuer, identity.Subject) || secondFactor && !expected.Use2fa {
		return ErrIdentity
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	policy, err := readPolicy(ctx, tx)
	if err != nil {
		return err
	}
	if !policy.Enabled || policy != identity.Policy {
		return ErrIdentity
	}
	// Binding writers use the exclusive form, with the same configuration,
	// binding and account lock order as this admission path.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock_shared(684627916)`); err != nil {
		return err
	}
	var revision int64
	var active bool
	var current ent.User
	err = tx.QueryRowContext(ctx, `SELECT a.revision,b.active,coalesce(u.openid,false),coalesce(u.passwd,false),coalesce(u.register,''),coalesce(u.use2fa,false),coalesce(u.totp_secret_confirmed,false),coalesce(u.totp_secret,'') FROM uem_oidc_bindings b JOIN uem_oidc_accounts a ON a.user_id=b.user_id JOIN users u ON u.uid=a.user_id WHERE b.issuer=$1 AND b.subject=$2 AND b.user_id=$3 FOR UPDATE OF u`, policy.Issuer, identity.Subject, identity.UserID).Scan(&revision, &active, &current.Openid, &current.Passwd, &current.Register, &current.Use2fa, &current.TotpSecretConfirmed, &current.TotpSecret)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrIdentity
	}
	if err != nil {
		return err
	}
	if !active || revision != identity.Revision || !current.Openid || current.Passwd || current.Use2fa != expected.Use2fa || current.TotpSecret != expected.TotpSecret {
		return ErrIdentity
	}
	if secondFactor {
		if !current.TotpSecretConfirmed {
			return ErrIdentity
		}
	} else if current.TotpSecretConfirmed != expected.TotpSecretConfirmed {
		return ErrIdentity
	}
	// Preserve configured initial auto-approval for a still-pending account,
	// while never undoing review imposed after an earlier approval or MFA step.
	approved := current.Register == nats.REGISTER_APPROVED || current.Register == nats.REGISTER_COMPLETE
	initialApproval := !secondFactor && policy.AutoApprove && current.Register == nats.REGISTER_IN_REVIEW && expected.Register == nats.REGISTER_IN_REVIEW
	if !approved && !initialApproval {
		return ErrIdentity
	}
	if secondFactor {
		identityJSON, err := json.Marshal(identity)
		if err != nil {
			return err
		}
		if err = mfaadmission.Consume(ctx, tx, expected.ID, loginproof.OpenID, loginproof.Digest(string(identityJSON)), evidence); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE users SET register=$2,cert_clear_password='',modified=clock_timestamp() WHERE uid=$1`, expected.ID, nats.REGISTER_COMPLETE); err != nil {
		return err
	}
	return tx.Commit()
}
