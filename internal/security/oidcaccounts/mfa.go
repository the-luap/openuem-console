package oidcaccounts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
)

// MFAAuthorization is captured from server-side session state. Its constructors
// distinguish a pending first-factor flow from an authenticated account session.
type MFAAuthorization struct {
	identity       Session
	primary        string
	requirePrimary bool
}

func PrimaryMFA(identity Session, proof string) MFAAuthorization {
	return MFAAuthorization{identity: identity, primary: proof, requirePrimary: true}
}

func AccountMFA(identity Session) MFAAuthorization {
	return MFAAuthorization{identity: identity}
}

// Validate checks the immutable session evidence, including the first-factor
// lifetime for public enrollment. Call it again before committing a mutation.
func (a MFAAuthorization) Validate(expected *ent.User, now time.Time) error {
	if expected == nil || expected.ID == "" || !expected.Openid || expected.Passwd || a.identity.UserID != expected.ID || a.identity.Revision <= 0 || !validIdentity(a.identity.Policy.Issuer, a.identity.Subject) {
		return ErrIdentity
	}
	if a.requirePrimary {
		proof, err := loginproof.Read(a.primary, expected.ID, now)
		encoded, marshalErr := json.Marshal(a.identity)
		if err != nil || marshalErr != nil || !expected.Use2fa || proof.Method != loginproof.OpenID || proof.Credential != loginproof.Digest(string(encoded)) {
			return ErrIdentity
		}
	}
	return nil
}

// Lock binds an MFA mutation to the current complete policy and active binding
// revision in the caller's read-committed transaction. Call before locking users;
// configuration, binding and account locks must remain held through the write.
// The caller must also compare the locked account's full enrollment snapshot.
func (a MFAAuthorization) Lock(ctx context.Context, tx *sql.Tx, expected *ent.User) error {
	if err := a.Validate(expected, time.Now()); err != nil {
		return err
	}
	policy, err := readPolicy(ctx, tx)
	if err != nil {
		return err
	}
	if !policy.Enabled || policy != a.identity.Policy {
		return ErrIdentity
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock_shared(684627916)`); err != nil {
		return err
	}
	var revision int64
	var active bool
	err = tx.QueryRowContext(ctx, `SELECT a.revision,b.active FROM uem_oidc_bindings b JOIN uem_oidc_accounts a ON a.user_id=b.user_id WHERE b.issuer=$1 AND b.subject=$2 AND b.user_id=$3 FOR SHARE OF a,b`, policy.Issuer, a.identity.Subject, a.identity.UserID).Scan(&revision, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrIdentity
	}
	if err != nil {
		return err
	}
	if !active || revision != a.identity.Revision {
		return ErrIdentity
	}
	return nil
}
