package oidcaccounts_test

import (
	"context"
	"errors"
	"testing"

	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/security/oidcaccounts"
)

func TestOIDCSessionUsesLiveIdentityRevisionAndPolicy(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	if err := f.change(t, "admin", "reader", "session-subject", "link", 0); err != nil {
		t.Fatal(err)
	}
	session, err := f.s.SessionFor(ctx, f.p, "reader", "session-subject")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.ValidateSession(ctx, *session); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"uid", "subject", "revision", "policy"} {
		changed := *session
		switch mode {
		case "uid":
			changed.UserID = "admin"
		case "subject":
			changed.Subject = "other"
		case "revision":
			changed.Revision = 0
		case "policy":
			changed.Policy.ClientID = "other"
		}
		if err = f.s.ValidateSession(ctx, changed); !errors.Is(err, oidcaccounts.ErrIdentity) {
			t.Fatal("modified session evidence accepted", mode, err)
		}
	}
	if err = f.change(t, "admin", "reader", "session-subject", "disable", 1); err != nil {
		t.Fatal(err)
	}
	if err = f.s.ValidateSession(ctx, *session); !errors.Is(err, oidcaccounts.ErrIdentity) {
		t.Fatal("disabled identity session accepted", err)
	}
	if err = f.change(t, "admin", "reader", "session-subject", "enable", 2); err != nil {
		t.Fatal(err)
	}
	if err = f.s.ValidateSession(ctx, *session); !errors.Is(err, oidcaccounts.ErrIdentity) {
		t.Fatal("old session revived after reenable", err)
	}
	session, err = f.s.SessionFor(ctx, f.p, "reader", "session-subject")
	if err != nil {
		t.Fatal(err)
	}
	account, err := f.m.Client.User.Get(ctx, "reader")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.m.Client.User.UpdateOneID("reader").SetRegister(nats.REGISTER_REVOKED).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err = f.s.ValidateSession(ctx, *session); !errors.Is(err, oidcaccounts.ErrIdentity) {
		t.Fatal("revoked account session accepted", err)
	}
	if err = f.s.AdmitSession(ctx, *session, account, false); err == nil {
		t.Fatal("login confirmation reactivated revoked account")
	}
	if err = f.m.Client.User.UpdateOneID("reader").SetRegister(nats.REGISTER_IN_REVIEW).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err = f.s.ValidateSession(ctx, *session); !errors.Is(err, oidcaccounts.ErrIdentity) {
		t.Fatal("unapproved account session accepted", err)
	}
	if err = f.m.Client.User.UpdateOneID("reader").SetRegister(nats.REGISTER_APPROVED).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err = f.m.Client.User.UpdateOneID("reader").SetPasswd(true).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err = f.s.ValidateSession(ctx, *session); !errors.Is(err, oidcaccounts.ErrIdentity) {
		t.Fatal("account mode change retained OIDC session", err)
	}
	if err = f.m.Client.User.UpdateOneID("reader").SetPasswd(false).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	settings, err := f.m.GetAuthenticationSettings()
	if err != nil {
		t.Fatal(err)
	}
	if err = settings.Update().SetOIDCRole("different-role").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err = f.s.ValidateSession(ctx, *session); !errors.Is(err, oidcaccounts.ErrIdentity) {
		t.Fatal("policy change retained session", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err = f.s.ValidateSession(canceled, *session); !errors.Is(err, context.Canceled) {
		t.Fatal("session validation suppressed database cancellation", err)
	}
}
