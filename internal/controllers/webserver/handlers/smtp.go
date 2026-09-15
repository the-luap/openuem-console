package handlers

import (
	"context"
	"crypto/tls"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/nats/smtptransport"
	"github.com/open-uem/openuem-console/internal/security/access"
	consolesettings "github.com/open-uem/openuem-console/internal/settings"
	"github.com/open-uem/openuem-console/internal/views/admin_views"
	"github.com/wneessen/go-mail"
)

func smtpFailure(err error) error {
	status, message := http.StatusServiceUnavailable, "SMTP settings are unavailable. A completed save or test may already be recorded; reload before trying again."
	switch {
	case errors.Is(err, access.ErrDenied):
		status, message = http.StatusForbidden, "Only current server administrators can manage SMTP settings."
	case errors.Is(err, consolesettings.ErrInvalid):
		status, message = http.StatusBadRequest, "Invalid SMTP request. Check the fields and explicit password action."
	case errors.Is(err, consolesettings.ErrNotFound):
		status, message = http.StatusNotFound, "SMTP settings were not found in this scope."
	case errors.Is(err, consolesettings.ErrConflict):
		status, message = http.StatusConflict, "SMTP settings changed or cannot be safely edited. Reload before continuing."
	case errors.Is(err, consolesettings.ErrSecret):
		message = "The SMTP password could not be securely stored or read. Verify the configured encryption key."
	case errors.Is(err, consolesettings.ErrRecent):
		status, message = http.StatusTooManyRequests, "An SMTP test was attempted recently. Wait one minute before starting another."
	}
	return echo.NewHTTPError(status, message)
}

func smtpScope(c echo.Context) (access.Scope, string, error) {
	scope := access.Scope{}
	base := "/admin/smtp"
	if raw := c.Param("tenant"); raw != "" {
		id, err := strconv.Atoi(raw)
		if err != nil || id <= 0 || strconv.Itoa(id) != raw {
			return scope, "", consolesettings.ErrInvalid
		}
		scope.TenantID = id
		base = "/tenant/" + raw + base
	}
	if c.Param("site") != "" {
		return scope, "", consolesettings.ErrInvalid
	}
	return scope, base, nil
}

func smtpForm(c echo.Context, test bool) (url.Values, error) {
	r := c.Request()
	limit := int64(64 << 10)
	if test {
		limit = 8192
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Encoding") != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return nil, consolesettings.ErrInvalid
	}
	if r.ContentLength > limit {
		return nil, echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Form is too large")
	}
	r.Body = http.MaxBytesReader(c.Response(), r.Body, limit)
	if err = r.ParseForm(); err != nil {
		return nil, consolesettings.ErrInvalid
	}
	if int64(len(r.PostForm.Encode())) > limit {
		return nil, consolesettings.ErrInvalid
	}
	for key, values := range r.PostForm {
		if len(values) != 1 || !utf8.ValidString(values[0]) || strings.ContainsRune(values[0], 0) {
			return nil, consolesettings.ErrInvalid
		}
		max := 128
		switch key {
		case "csrf", "settingsId", "revision":
		case "attempt", "confirm":
			if !test {
				return nil, consolesettings.ErrInvalid
			}
		case "server", "port", "user", "auth", "mail-from", "encryption", "password-action":
			if test {
				return nil, consolesettings.ErrInvalid
			}
			max = 1024
		case "password":
			if test {
				return nil, consolesettings.ErrInvalid
			}
			max = 16384
		default:
			return nil, consolesettings.ErrInvalid
		}
		if len(values[0]) > max {
			return nil, consolesettings.ErrInvalid
		}
	}
	return r.PostForm, nil
}

func smtpRedirect(c echo.Context, path string) error {
	if c.Request().Header.Get("HX-Request") == "true" {
		c.Response().Header().Set("HX-Redirect", path)
		return c.NoContent(http.StatusNoContent)
	}
	return c.Redirect(http.StatusSeeOther, path)
}

func (h *Handler) SMTPSettings(c echo.Context) error {
	r := c.Request()
	c.Response().Header().Set("Cache-Control", "no-store")
	scope, base, err := smtpScope(c)
	if err != nil {
		return smtpFailure(err)
	}
	values := url.Values{}
	switch r.Method {
	case http.MethodPost:
		values, err = smtpForm(c, false)
		if err != nil {
			return smtpFormFailure(err)
		}
	case http.MethodGet:
		if r.ContentLength != 0 || r.Header.Get("Content-Encoding") != "" || r.URL.ForceQuery || len(r.URL.RawQuery) > 64 {
			return smtpFailure(consolesettings.ErrInvalid)
		}
		values, err = url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return smtpFailure(consolesettings.ErrInvalid)
		}
		for key, v := range values {
			if key != "saved" || len(v) != 1 || v[0] != "1" {
				return smtpFailure(consolesettings.ErrInvalid)
			}
		}
	default:
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	store, err := consolesettings.NewSMTPStore(h.Model.DB, h.Access, h.EncryptionMasterKey)
	if err != nil {
		return smtpFailure(err)
	}
	if r.Method == http.MethodPost {
		id, err := tagID(values.Get("settingsId"))
		if err != nil {
			return smtpFailure(consolesettings.ErrInvalid)
		}
		port, err := strconv.Atoi(values.Get("port"))
		if err != nil || strconv.Itoa(port) != values.Get("port") {
			return smtpFailure(consolesettings.ErrInvalid)
		}
		cfg := consolesettings.SMTPConfig{Server: values.Get("server"), Port: port, User: values.Get("user"), Auth: values.Get("auth"), From: values.Get("mail-from"), Encryption: values.Get("encryption")}
		if err = store.Save(r.Context(), info.Principal.UserID, scope, id, values.Get("revision"), cfg, values.Get("password-action"), values.Get("password")); err != nil {
			return smtpFailure(err)
		}
		return smtpRedirect(c, base+"?saved=1")
	}
	review, err := store.Read(r.Context(), info.Principal.UserID, scope)
	if err != nil {
		return smtpFailure(err)
	}
	return RenderView(c, admin_views.SMTPSettingsIndex(" | SMTP settings", admin_views.SMTPSettings(c, review, info, base, values.Get("saved") == "1", uuid.NewString()), info))
}

func smtpFormFailure(err error) error {
	var httpError *echo.HTTPError
	if errors.As(err, &httpError) {
		return err
	}
	return smtpFailure(err)
}

func (h *Handler) TestSMTPSettings(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	if c.Request().Method != http.MethodPost {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	scope, base, err := smtpScope(c)
	if err != nil {
		return smtpFailure(err)
	}
	values, err := smtpForm(c, true)
	if err != nil {
		return smtpFormFailure(err)
	}
	if values.Get("confirm") != "send" {
		return smtpFailure(consolesettings.ErrInvalid)
	}
	id, err := tagID(values.Get("settingsId"))
	if err != nil {
		return smtpFailure(consolesettings.ErrInvalid)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	store, err := consolesettings.NewSMTPStore(h.Model.DB, h.Access, h.EncryptionMasterKey)
	if err != nil {
		return smtpFailure(err)
	}
	send := h.smtpTestSender
	if send == nil {
		send = sendSavedSMTPTest
	}
	if _, err = store.Test(c.Request().Context(), info.Principal.UserID, scope, id, values.Get("revision"), values.Get("attempt"), send); err != nil {
		return smtpFailure(err)
	}
	return smtpRedirect(c, base)
}

func sendSavedSMTPTest(ctx context.Context, cfg consolesettings.SMTPConfig, password string) error {
	tlsOptions := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.Server}
	var implicitTLS *tls.Config
	if cfg.Encryption == "smtps" {
		implicitTLS = tlsOptions
	}
	transport := smtptransport.New(ctx, implicitTLS)
	defer transport.Close()
	options := []mail.Option{mail.WithPort(cfg.Port), mail.WithTLSConfig(tlsOptions), mail.WithDialContextFunc(transport.DialContext)}
	if cfg.Auth != "NOAUTH" {
		options = append(options, mail.WithSMTPAuth(mail.SMTPAuthType(cfg.Auth)), mail.WithUsername(cfg.User), mail.WithPassword(password))
	}
	client, err := mail.NewClient(cfg.Server, options...)
	if err != nil {
		return err
	}
	if cfg.Encryption == "smtps" {
		client.SetSSL(true)
	}
	if cfg.Encryption == "starttls" {
		client.SetTLSPolicy(mail.TLSMandatory)
	}
	message := mail.NewMsg()
	if err = message.From(cfg.From); err != nil {
		return err
	}
	if err = message.To(cfg.From); err != nil {
		return err
	}
	message.Subject("OpenUEM SMTP configuration test")
	message.SetBodyString(mail.TypeTextPlain, "This message was requested by an OpenUEM administrator to test the saved SMTP configuration.")
	return client.DialAndSendWithContext(ctx, message)
}
