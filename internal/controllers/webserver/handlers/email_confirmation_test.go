package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent/enttest"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/controllers/router/middleware"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/stretchr/testify/require"
)

func TestEmailConfirmationRejectsInvalidProofAndAccountState(t *testing.T) {
	for _, name := range []string{"valid", "wrong-subject", "wrong-issuer", "missing-expiry", "expired", "missing-issued", "long-lifetime", "future-issued", "future-not-before", "empty-id", "missing-key", "wrong-method", "missing-binding", "oversized", "malformed", "revoked", "approved", "password", "openid", "verified", "missing-csrf", "missing-settings"} {
		t.Run(name, func(t *testing.T) {
			client := enttest.Open(t, "sqlite3", "file:email-confirmation?mode=memory&_fk=1")
			t.Cleanup(func() { client.Close() })
			ctx, err := locales.WithLocale(t.Context(), "en")
			require.NoError(t, err)
			create := client.User.Create().SetID("confirmation-user").SetName("Confirmation user").SetEmail("confirmation@example.test")
			switch name {
			case "revoked":
				create.SetRegister(openuem.REGISTER_REVOKED)
			case "approved":
				create.SetRegister(openuem.REGISTER_APPROVED)
			case "password":
				create.SetPasswd(true)
			case "openid":
				create.SetOpenid(true)
			case "verified":
				create.SetEmailVerified(true)
			}
			before, err := create.Save(ctx)
			require.NoError(t, err)
			if name != "missing-settings" {
				require.NoError(t, client.Settings.Create().Exec(ctx))
			}
			h := &Handler{Model: &models.Model{Client: client}, JWTKey: strings.Repeat("j", 32)}
			claims := jwt.RegisteredClaims{ID: before.ID, Subject: "Email Confirmation", Issuer: "OpenUEM", IssuedAt: jwt.NewNumericDate(time.Now()), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}
			method := jwt.SigningMethodHS512
			switch name {
			case "wrong-subject":
				claims.Subject = "New password"
			case "wrong-issuer":
				claims.Issuer = "Other issuer"
			case "missing-expiry":
				claims.ExpiresAt = nil
			case "expired":
				claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
			case "missing-issued":
				claims.IssuedAt = nil
			case "long-lifetime":
				claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(25 * time.Hour))
			case "future-issued":
				claims.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
			case "future-not-before":
				claims.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Hour))
			case "empty-id":
				claims.ID = ""
			case "missing-key":
				h.JWTKey = ""
			case "wrong-method":
				method = jwt.SigningMethodHS256
			}
			proof := emailConfirmationClaims{RegisteredClaims: claims, AccountBinding: models.EmailConfirmationBinding(before)}
			if name == "missing-binding" {
				proof.AccountBinding = ""
			}
			encoded, err := jwt.NewWithClaims(method, proof).SignedString([]byte(h.JWTKey))
			require.NoError(t, err)
			if name == "oversized" {
				encoded += strings.Repeat("x", 8192)
			}
			if name == "malformed" {
				encoded = "owned-private-invalid-confirmation"
			}
			recorder := httptest.NewRecorder()
			c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/auth/confirm/owned", nil).WithContext(ctx), recorder)
			c.SetParamNames("token")
			c.SetParamValues(encoded)
			if name != "missing-csrf" {
				c.Set("csrf", "owned-csrf")
			}
			var result error
			require.NotPanics(t, func() { result = h.ConfirmEmail(c) })
			after, err := client.User.Get(ctx, before.ID)
			require.NoError(t, err)
			if name == "valid" {
				require.NoError(t, result)
				require.False(t, after.EmailVerified, "opening the link must not confirm the address")
				require.Equal(t, before.Register, after.Register)
				require.Contains(t, recorder.Body.String(), `method="post"`)
				post := httptest.NewRequest(http.MethodPost, "/auth/confirm/owned", strings.NewReader(url.Values{"csrf": {"owned-csrf"}}.Encode())).WithContext(ctx)
				post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				c.SetRequest(post)
				require.NoError(t, h.ConfirmEmail(c))
				after, err = client.User.Get(ctx, before.ID)
				require.NoError(t, err)
				require.True(t, after.EmailVerified)
				require.Equal(t, openuem.REGISTER_SEND_CERTIFICATE, after.Register)
				require.Error(t, h.ConfirmEmail(c), "a second confirmation must fail")
			} else {
				var failure *echo.HTTPError
				require.True(t, errors.As(result, &failure), "invalid proof or state was accepted")
				status := http.StatusBadRequest
				if name == "missing-csrf" {
					status = http.StatusForbidden
				}
				if name == "missing-settings" {
					status = http.StatusInternalServerError
				}
				require.Equal(t, status, failure.Code)
				if status == http.StatusBadRequest {
					require.Equal(t, "This confirmation link is invalid or expired. Ask your administrator for a new confirmation email.", failure.Message)
				}
				require.Equal(t, before.EmailVerified, after.EmailVerified, "rejected confirmation changed verification")
				require.Equal(t, before.Register, after.Register, "rejected confirmation changed account status")
			}
			require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
			require.Equal(t, "no-referrer", recorder.Header().Get("Referrer-Policy"))
			if name != "valid" {
				require.NotContains(t, recorder.Body.String(), encoded)
			}
		})
	}
}

func TestEmailConfirmationRejectsRecipientAndAccountReplacement(t *testing.T) {
	for _, change := range []string{"address", "account"} {
		t.Run(change, func(t *testing.T) {
			client := enttest.Open(t, "sqlite3", "file:email-confirmation-binding?mode=memory&_fk=1")
			t.Cleanup(func() { client.Close() })
			ctx, err := locales.WithLocale(t.Context(), "en")
			require.NoError(t, err)
			require.NoError(t, client.Settings.Create().Exec(ctx))
			account, err := client.User.Create().SetID("recipient-account").SetName("Recipient account").SetEmail("original@example.test").Save(ctx)
			require.NoError(t, err)
			h := &Handler{Model: &models.Model{Client: client}, JWTKey: strings.Repeat("j", 32)}
			encoded, err := h.generateConfirmationToken(account)
			require.NoError(t, err)
			if change == "address" {
				require.NoError(t, client.User.UpdateOneID(account.ID).SetEmail("changed-private-recipient@example.test").Exec(ctx))
			} else {
				require.NoError(t, client.User.DeleteOneID(account.ID).Exec(ctx))
				require.NoError(t, client.User.Create().SetID(account.ID).SetName("Replacement account").SetEmail(account.Email).SetCreated(account.Created.Add(time.Microsecond)).Exec(ctx))
			}
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				r := httptest.NewRequest(method, "/auth/confirm/owned", strings.NewReader("csrf=owned-csrf")).WithContext(ctx)
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()
				c := echo.New().NewContext(r, w)
				c.Set("csrf", "owned-csrf")
				c.SetParamNames("token")
				c.SetParamValues(encoded)
				var rejected *echo.HTTPError
				require.ErrorAs(t, h.ConfirmEmail(c), &rejected)
				require.Equal(t, http.StatusBadRequest, rejected.Code)
				require.NotContains(t, w.Body.String(), "changed-private-recipient")
				current, err := client.User.Get(ctx, account.ID)
				require.NoError(t, err)
				require.False(t, current.EmailVerified)
				require.Equal(t, account.Register, current.Register)
			}
		})
	}
}

func TestEmailConfirmationRoutesRequireExplicitBoundedPOST(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:email-confirmation-routes?mode=memory&_fk=1")
	t.Cleanup(func() { client.Close() })
	user, err := client.User.Create().SetID("confirmation-route-user").SetName("Confirmation user").SetEmail("confirmation@example.test").Save(t.Context())
	require.NoError(t, err)
	require.NoError(t, client.Settings.Create().Exec(t.Context()))
	h := &Handler{Model: &models.Model{Client: client}, JWTKey: strings.Repeat("j", 32)}
	encoded, err := h.generateConfirmationToken(user)
	require.NoError(t, err)
	e := echo.New()
	e.Use(middleware.GetLocale)
	e.Use(middleware.CSRF())
	h.Register(e, 1)
	target := "https://console.example.test/auth/confirm/" + encoded
	send := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		require.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
		return w
	}
	var cookie *http.Cookie
	var preview *httptest.ResponseRecorder
	for range 2 {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		preview = send(r)
		require.Equal(t, http.StatusOK, preview.Code)
		require.Contains(t, preview.Body.String(), "Confirm email address")
		require.Contains(t, preview.Body.String(), user.Email)
		for _, candidate := range preview.Result().Cookies() {
			if candidate.Name == "__Host-openuem-csrf" {
				cookie = candidate
			}
		}
		current, err := client.User.Get(t.Context(), user.ID)
		require.NoError(t, err)
		require.False(t, current.EmailVerified, "link scanner consumed confirmation")
		require.Equal(t, user.Register, current.Register)
	}
	require.NotNil(t, cookie)
	for _, method := range []string{http.MethodHead, http.MethodPut, http.MethodDelete} {
		r := httptest.NewRequest(method, target, nil)
		r.AddCookie(cookie)
		r.Header.Set("X-CSRF-Token", cookie.Value)
		require.Equal(t, http.StatusMethodNotAllowed, send(r).Code)
		current, err := client.User.Get(t.Context(), user.ID)
		require.NoError(t, err)
		require.False(t, current.EmailVerified)
	}
	for _, name := range []string{"missing-cookie", "missing-token", "wrong-token", "query-token", "duplicate-token", "unknown-field", "foreign-origin", "cross-site", "json", "large", "chunked-large", "header-large", "preparsed-large", "query-action"} {
		t.Run(name, func(t *testing.T) {
			form := url.Values{"csrf": {cookie.Value}}
			action, status := target, http.StatusForbidden
			switch name {
			case "missing-token":
				form.Del("csrf")
			case "wrong-token":
				form.Set("csrf", "incorrect")
			case "query-token":
				action += "?csrf=" + url.QueryEscape(cookie.Value)
				form.Del("csrf")
			case "duplicate-token":
				form.Add("csrf", cookie.Value)
			case "unknown-field":
				form.Set("account", "another-account")
			case "json":
				status = http.StatusUnsupportedMediaType
			case "large", "chunked-large", "header-large", "preparsed-large":
				form.Set("extra", strings.Repeat("x", 8192))
				status = http.StatusRequestEntityTooLarge
			case "query-action":
				action += "?extra=value"
				status = http.StatusBadRequest
			}
			r := httptest.NewRequest(http.MethodPost, action, strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if name != "missing-cookie" {
				r.AddCookie(cookie)
			}
			if name == "foreign-origin" {
				r.Header.Set("Origin", "https://untrusted.invalid")
			}
			if name == "cross-site" {
				r.Header.Set("Sec-Fetch-Site", "cross-site")
			}
			if name == "json" {
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-CSRF-Token", cookie.Value)
			}
			if name == "chunked-large" {
				r.ContentLength = -1
			}
			if name == "header-large" || name == "preparsed-large" {
				r.Header.Set("X-CSRF-Token", cookie.Value)
			}
			if name == "preparsed-large" {
				r.PostForm = form
				r.ContentLength = -1
			}
			require.Equal(t, status, send(r).Code)
			current, err := client.User.Get(t.Context(), user.ID)
			require.NoError(t, err)
			require.False(t, current.EmailVerified)
			require.Equal(t, user.Register, current.Register)
		})
	}
	post := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(url.Values{"csrf": {cookie.Value}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://console.example.test")
		r.AddCookie(cookie)
		return r
	}
	complete := send(post())
	require.Equal(t, http.StatusOK, complete.Code)
	current, err := client.User.Get(t.Context(), user.ID)
	require.NoError(t, err)
	require.True(t, current.EmailVerified)
	require.Equal(t, openuem.REGISTER_SEND_CERTIFICATE, current.Register)
	require.NotContains(t, complete.Body.String(), encoded)
	require.Equal(t, http.StatusBadRequest, send(post()).Code)
	require.Equal(t, http.StatusBadRequest, send(httptest.NewRequest(http.MethodGet, target, nil)).Code)
	if directory := os.Getenv("ACCOUNT_CONFIRMATION_UI_ARTIFACTS"); directory != "" {
		require.NoError(t, os.MkdirAll(directory, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(directory, "email-confirmation-preview.html"), preview.Body.Bytes(), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(directory, "email-confirmation-complete.html"), complete.Body.Bytes(), 0644))
	}
}
