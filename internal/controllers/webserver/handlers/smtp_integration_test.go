package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/ent/settings"
	"github.com/open-uem/ent/tenant"
	"github.com/open-uem/nats/legacysecret"
	"github.com/open-uem/openuem-console/internal/security/access"
	consolesettings "github.com/open-uem/openuem-console/internal/settings"
	"github.com/stretchr/testify/require"
)

func exerciseSMTPSettingsRoutes(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenantID int) {
	t.Helper()
	originalKey, originalSender := h.EncryptionMasterKey, h.smtpTestSender
	h.EncryptionMasterKey = strings.Repeat("k", 32)
	defer func() { h.EncryptionMasterKey = originalKey; h.smtpTestSender = originalSender }()
	store, err := consolesettings.NewSMTPStore(h.Model.DB, h.Access, h.EncryptionMasterKey)
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	requests := ownedTagHTTPRequest(t, h, e, ctx)
	calls := 0
	h.smtpTestSender = func(ctx context.Context, cfg consolesettings.SMTPConfig, password string) error {
		calls++
		require.True(t, password == "owned-http-smtp-private")
		require.Equal(t, "owned@example.invalid", cfg.From)
		return nil
	}
	for _, scope := range []access.Scope{{}, {TenantID: tenantID}} {
		base := "/admin/smtp"
		query := h.Model.Client.Settings.Query().Where(settings.Not(settings.HasTenant()))
		if scope.TenantID > 0 {
			base = fmt.Sprintf("/tenant/%d/admin/smtp", scope.TenantID)
			query = h.Model.Client.Settings.Query().Where(settings.HasTenantWith(tenant.ID(scope.TenantID)))
		}
		original, err := query.Only(ctx)
		if err != nil {
			require.True(t, ent.IsNotFound(err))
			original, err = h.Model.Client.Settings.Create().SetTenantID(scope.TenantID).Save(ctx)
			require.NoError(t, err)
			defer h.Model.Client.Settings.DeleteOneID(original.ID).Exec(ctx)
		} else {
			defer h.Model.Client.Settings.UpdateOneID(original.ID).SetSMTPServer(original.SMTPServer).SetSMTPPort(original.SMTPPort).SetSMTPUser(original.SMTPUser).SetSMTPPassword(original.SMTPPassword).SetSMTPAuth(original.SMTPAuth).SetMessageFrom(original.MessageFrom).SetSMTPEncryptionType(original.SMTPEncryptionType).Exec(ctx)
		}
		require.NoError(t, h.Model.Client.Settings.UpdateOneID(original.ID).SetSMTPPassword("owned-preexisting-private").Exec(ctx))
		review, err := store.Read(ctx, "apple-console-admin", scope)
		require.NoError(t, err)
		form := url.Values{"settingsId": {fmt.Sprint(review.ID)}, "revision": {review.Revision}, "server": {"smtp.example.invalid"}, "port": {"1587"}, "user": {"owned <user>"}, "auth": {"PLAIN"}, "mail-from": {"owned@example.invalid"}, "encryption": {"starttls"}, "password-action": {"replace"}, "password": {"owned-http-smtp-private"}}
		for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
			require.Equal(t, 403, requests(actor, "GET", base, nil, "").Code)
			require.Equal(t, 403, requests(actor, "POST", base, form, "console-test-token").Code)
			require.Equal(t, 403, requests(actor, "POST", base+"/test", form, "console-test-token").Code)
		}
		response := requests("apple-console-admin", "GET", base, nil, "")
		require.Equal(t, 200, response.Code)
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		require.NotContains(t, response.Body.String(), "owned-preexisting-private")
		require.Contains(t, response.Body.String(), "Keep stored password")
		require.Equal(t, 403, requests("apple-console-admin", "POST", base, form, "wrong").Code)
		bad := url.Values{}
		for key, values := range form {
			bad[key] = append([]string{}, values...)
		}
		bad["revision"] = []string{review.Revision, review.Revision}
		require.Equal(t, 400, requests("apple-console-admin", "POST", base, bad, "console-test-token").Code)
		require.Equal(t, 400, requests("apple-console-admin", "POST", base+"?password=private", form, "console-test-token").Code)
		large := url.Values{}
		for key, values := range form {
			large[key] = append([]string{}, values...)
		}
		large.Set("password", strings.Repeat("x", 65<<10))
		require.Equal(t, 413, requests("apple-console-admin", "POST", base, large, "console-test-token").Code)
		native := ownedTagHTTPRequest(t, h, e, ctx, func(r *http.Request) { r.Header.Del("X-CSRF-Token"); r.Header.Del("HX-Request") })
		form.Set("csrf", strings.Repeat("t", 32))
		response = native("apple-console-admin", "POST", base, form, "")
		require.Equal(t, 303, response.Code)
		require.Equal(t, base+"?saved=1", response.Header().Get("Location"))
		require.Equal(t, 409, requests("apple-console-admin", "POST", base, form, "console-test-token").Code)
		stored, err := h.Model.Client.Settings.Get(ctx, original.ID)
		require.NoError(t, err)
		plain, err := legacysecret.Open(stored.SMTPPassword, h.EncryptionMasterKey)
		require.NoError(t, err)
		require.True(t, plain == "owned-http-smtp-private")
		require.Equal(t, 1587, stored.SMTPPort)
		response = requests("apple-console-admin", "GET", base+"?saved=1", nil, "")
		require.Equal(t, 200, response.Code)
		require.NotContains(t, response.Body.String(), stored.SMTPPassword)
		require.NotContains(t, response.Body.String(), plain)
		review, err = store.Read(ctx, "apple-console-admin", scope)
		require.NoError(t, err)
		test := url.Values{"settingsId": {fmt.Sprint(review.ID)}, "revision": {review.Revision}, "attempt": {uuid.NewString()}, "confirm": {"send"}}
		before := calls
		response = requests("apple-console-admin", "POST", base+"/test", test, "console-test-token")
		require.Equal(t, 204, response.Code)
		require.Equal(t, base, response.Header().Get("HX-Redirect"))
		require.Equal(t, before+1, calls)
		response = requests("apple-console-admin", "POST", base+"/test", test, "console-test-token")
		require.Equal(t, 204, response.Code)
		require.Equal(t, base, response.Header().Get("HX-Redirect"))
		require.Equal(t, before+1, calls)
		response = requests("apple-console-admin", "GET", base, nil, "")
		require.Equal(t, 200, response.Code)
		require.Contains(t, response.Body.String(), "SMTP server accepted your last test message")
		require.NotContains(t, response.Body.String(), plain)
		test.Set("attempt", uuid.NewString())
		test.Set("password", "attempted-extra-secret")
		require.Equal(t, 400, requests("apple-console-admin", "POST", base+"/test", test, "console-test-token").Code)
		require.Equal(t, before+1, calls)
		if scope.TenantID > 0 {
			form.Set("revision", review.Revision)
			require.Equal(t, 404, requests("apple-console-admin", "POST", "/admin/smtp", form, "console-test-token").Code)
		}
	}
}
