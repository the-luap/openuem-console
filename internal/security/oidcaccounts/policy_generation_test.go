package oidcaccounts_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/oidcaccounts"
	"github.com/stretchr/testify/require"
)

func TestOIDCPolicyGenerationRejectsRestoredConfigurationAcrossAdmissionAndMFA(t *testing.T) {
	for _, field := range []string{"use_oidc", "oidc_issuer_url", "oidc_client_id", "oidc_provider", "oidc_role", "oidc_auto_create_account", "oidc_auto_approve"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture(t)
			ctx := t.Context()
			require.NoError(t, f.change(t, "admin", "reader", "generation-subject", "link", 0))
			original, err := f.s.SessionFor(ctx, f.p, "reader", "generation-subject")
			require.NoError(t, err)
			user, err := f.m.Client.User.Get(ctx, "reader")
			require.NoError(t, err)
			var old any
			switch field {
			case "use_oidc":
				old = f.p.Enabled
			case "oidc_issuer_url":
				old = f.p.Issuer
			case "oidc_client_id":
				old = f.p.ClientID
			case "oidc_provider":
				old = f.p.Provider
			case "oidc_role":
				old = f.p.Role
			case "oidc_auto_create_account":
				old = f.p.AutoCreate
			case "oidc_auto_approve":
				old = f.p.AutoApprove
			}
			var changed any
			if value, ok := old.(bool); ok {
				changed = !value
			} else {
				changed = old.(string) + "-changed"
			}
			_, err = f.m.DB.ExecContext(ctx, `UPDATE authentications SET `+field+`=$1`, changed)
			require.NoError(t, err)
			var intermediate string
			require.NoError(t, f.m.DB.QueryRowContext(ctx, `SELECT generation::text FROM uem_oidc_policy_generation WHERE singleton`).Scan(&intermediate))
			require.NotEqual(t, f.p.Generation, intermediate)
			_, err = f.m.DB.ExecContext(ctx, `UPDATE authentications SET `+field+`=$1`, old)
			require.NoError(t, err)
			settings, err := f.m.GetAuthenticationSettings()
			require.NoError(t, err)
			fresh, err := f.s.CapturePolicy(ctx, oidcaccounts.PolicyFrom(settings))
			require.NoError(t, err)
			require.NotEqual(t, f.p.Generation, fresh.Generation)
			require.NotEqual(t, intermediate, fresh.Generation)
			require.ErrorIs(t, f.s.ValidateSession(ctx, *original), oidcaccounts.ErrIdentity)
			require.ErrorIs(t, f.s.AdmitSession(ctx, *original, user, nil), oidcaccounts.ErrIdentity)
			_, err = f.s.SessionFor(ctx, f.p, "reader", "generation-subject")
			require.ErrorIs(t, err, oidcaccounts.ErrIdentity)
			_, err = f.s.Resolve(ctx, f.p, oidcaccounts.Identity{Issuer: f.p.Issuer, Subject: "generation-subject"})
			require.ErrorIs(t, err, oidcaccounts.ErrConflict)
			tx, err := f.m.DB.BeginTx(ctx, nil)
			require.NoError(t, err)
			err = oidcaccounts.AccountMFA(*original).Lock(ctx, tx, user)
			require.NoError(t, tx.Rollback())
			require.ErrorIs(t, err, oidcaccounts.ErrIdentity)
			next, err := f.s.SessionFor(ctx, fresh, "reader", "generation-subject")
			require.NoError(t, err)
			require.Equal(t, original.Revision, next.Revision)
			require.NoError(t, f.s.ValidateSession(ctx, *next))
			require.NoError(t, f.s.AdmitSession(ctx, *next, user, nil))
			legacy := *next
			legacy.Policy.Generation = ""
			require.ErrorIs(t, f.s.ValidateSession(ctx, legacy), oidcaccounts.ErrIdentity)
			require.ErrorIs(t, f.s.AdmitSession(ctx, legacy, user, nil), oidcaccounts.ErrIdentity)
		})
	}
}

func TestOIDCPolicyGenerationPreservesRollbackUnrelatedChangesAndRestart(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	require.NoError(t, f.change(t, "admin", "reader", "generation-subject", "link", 0))
	original, err := f.s.SessionFor(ctx, f.p, "reader", "generation-subject")
	require.NoError(t, err)
	for _, query := range []string{
		`UPDATE authentications SET oidc_role=oidc_role`,
		`UPDATE authentications SET use_passwd=NOT coalesce(use_passwd,false),use_certificates=NOT coalesce(use_certificates,false),allow_register=NOT coalesce(allow_register,false),oidc_cookie_encription_key='owned replacement cookie key'`,
	} {
		_, err = f.m.DB.ExecContext(ctx, query)
		require.NoError(t, err)
		require.NoError(t, f.s.ValidateSession(ctx, *original))
	}
	tx, err := f.m.DB.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `UPDATE authentications SET oidc_role='rolled back role'`)
	require.NoError(t, err)
	var aborted string
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT generation::text FROM uem_oidc_policy_generation WHERE singleton`).Scan(&aborted))
	require.NotEqual(t, f.p.Generation, aborted)
	require.NoError(t, tx.Rollback())
	require.NoError(t, f.s.ValidateSession(ctx, *original))
	restarted, err := oidcaccounts.NewStore(f.m.DB, f.a)
	require.NoError(t, err)
	require.NoError(t, restarted.Migrate(ctx))
	require.NoError(t, restarted.ValidateSession(ctx, *original))
	values := f.p
	values.Generation = ""
	fresh, err := restarted.CapturePolicy(ctx, values)
	require.NoError(t, err)
	require.Equal(t, f.p, fresh)
	values.ClientID = "stale configuration"
	_, err = restarted.CapturePolicy(ctx, values)
	require.ErrorIs(t, err, oidcaccounts.ErrConflict)
	_, err = restarted.CapturePolicy(ctx, f.p)
	require.ErrorIs(t, err, oidcaccounts.ErrConflict)
}

func TestOIDCPolicyGenerationSurvivesConfigurationReplacement(t *testing.T) {
	for _, operation := range []string{"delete", "truncate"} {
		t.Run(operation, func(t *testing.T) {
			f := newFixture(t)
			ctx := t.Context()
			settings, err := f.m.GetAuthenticationSettings()
			require.NoError(t, err)
			query := `DELETE FROM authentications`
			if operation == "truncate" {
				query = `TRUNCATE authentications`
			}
			_, err = f.m.DB.ExecContext(ctx, query)
			require.NoError(t, err)
			_, err = f.m.DB.ExecContext(ctx, `INSERT INTO authentications(id,use_oidc,oidc_issuer_url,oidc_client_id,oidc_provider,oidc_role,oidc_auto_create_account,oidc_auto_approve) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, settings.ID, f.p.Enabled, f.p.Issuer, f.p.ClientID, f.p.Provider, f.p.Role, f.p.AutoCreate, f.p.AutoApprove)
			require.NoError(t, err)
			fresh, err := f.s.CapturePolicy(ctx, oidcaccounts.PolicyFrom(settings))
			require.NoError(t, err)
			require.NotEqual(t, f.p.Generation, fresh.Generation)
		})
	}
}

func TestOIDCPolicyGenerationReadsWaitForConfigurationTransaction(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "commit"}[commit], func(t *testing.T) {
			f := newFixture(t)
			ctx := t.Context()
			require.NoError(t, f.change(t, "admin", "reader", "generation-subject", "link", 0))
			original, err := f.s.SessionFor(ctx, f.p, "reader", "generation-subject")
			require.NoError(t, err)
			tx, err := f.m.DB.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer tx.Rollback()
			_, err = tx.ExecContext(ctx, `UPDATE authentications SET oidc_role='temporary'`)
			require.NoError(t, err)
			_, err = tx.ExecContext(ctx, `UPDATE authentications SET oidc_role=$1`, f.p.Role)
			require.NoError(t, err)
			bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			err = f.s.ValidateSession(bounded, *original)
			cancel()
			require.Error(t, err)
			require.False(t, errors.Is(err, oidcaccounts.ErrIdentity) || errors.Is(err, oidcaccounts.ErrConflict), "transient lock cancellation must not revoke identity")
			done := make(chan error, 1)
			go func() { done <- f.s.ValidateSession(ctx, *original) }()
			select {
			case err := <-done:
				t.Fatalf("validation overtook held configuration: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
			if commit {
				require.NoError(t, tx.Commit())
			} else {
				require.NoError(t, tx.Rollback())
			}
			select {
			case err := <-done:
				if commit {
					require.ErrorIs(t, err, oidcaccounts.ErrIdentity)
				} else {
					require.NoError(t, err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("validation did not resume after configuration transaction")
			}
		})
	}
}

func TestOIDCPolicyGenerationMigrationRejectsIncompleteProtection(t *testing.T) {
	for _, condition := range []string{"disabled-trigger", "missing-row"} {
		t.Run(condition, func(t *testing.T) {
			f := newFixture(t)
			ctx := t.Context()
			// Use committed owned fixture changes so migration sees the missing guard.
			var err error
			query := `ALTER TABLE authentications DISABLE TRIGGER uem_oidc_policy_generation`
			restore := `ALTER TABLE authentications ENABLE TRIGGER uem_oidc_policy_generation`
			if condition == "missing-row" {
				query = `DELETE FROM uem_oidc_policy_generation`
				restore = `INSERT INTO uem_oidc_policy_generation(singleton) VALUES(true)`
			}
			_, err = f.m.DB.ExecContext(ctx, query)
			require.NoError(t, err)
			failure := f.s.Migrate(ctx)
			if condition == "missing-row" {
				_, err = f.m.DB.ExecContext(ctx, `UPDATE authentications SET oidc_role='must fail'`)
				require.Error(t, err)
				_, err = f.s.CapturePolicy(ctx, oidcaccounts.Policy{Enabled: f.p.Enabled, Issuer: f.p.Issuer, ClientID: f.p.ClientID, Provider: f.p.Provider, Role: f.p.Role, AutoCreate: f.p.AutoCreate, AutoApprove: f.p.AutoApprove})
				require.ErrorIs(t, err, oidcaccounts.ErrConflict)
			}
			_, err = f.m.DB.ExecContext(ctx, restore)
			require.NoError(t, err)
			require.Error(t, failure)
			require.NoError(t, f.s.Migrate(ctx))
		})
	}
}

func TestOIDCPolicyGenerationTriggerUsesApplicationNamespace(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	var schema string
	require.NoError(t, f.m.DB.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&schema))
	tx, err := f.m.DB.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `SET LOCAL search_path=pg_catalog`)
	require.NoError(t, err)
	// The namespace is generated by the owned fixture, never external input.
	_, err = tx.ExecContext(ctx, `UPDATE "`+schema+`".authentications SET oidc_role='temporary'`)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `UPDATE "`+schema+`".authentications SET oidc_role=$1`, f.p.Role)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	values := f.p
	values.Generation = ""
	current, err := f.s.CapturePolicy(ctx, values)
	require.NoError(t, err)
	require.NotEqual(t, f.p.Generation, current.Generation)
}
