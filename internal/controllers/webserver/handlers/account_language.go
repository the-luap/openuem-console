package handlers

import (
	"errors"
	"mime"
	"net/http"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/preferences"
	"github.com/open-uem/openuem-console/internal/views/account_views"
	"github.com/open-uem/openuem-console/internal/views/locales"
)

const accountLanguageKey = "openuem.account.language"

func (h *Handler) accountLanguage(c echo.Context) account_views.LanguageData {
	if value, ok := c.Get(accountLanguageKey).(account_views.LanguageData); ok {
		return value
	}
	value := account_views.LanguageData{Unavailable: true}
	if h.Preferences != nil {
		uid := h.SessionManager.Manager.GetString(c.Request().Context(), "uid")
		if uid != "" {
			code, err := h.Preferences.Language(c.Request().Context(), uid)
			if err == nil {
				value = account_views.LanguageData{Selected: code}
			}
		}
	}
	c.Set(accountLanguageKey, value)
	return value
}

// UserLocale runs after the session middleware. Preferences are loaded for each
// request, so existing sessions do not retain another account's or an old choice.
// A preference outage leaves the browser-selected locale usable.
func (h *Handler) UserLocale(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		language := h.accountLanguage(c)
		if !language.Unavailable && language.Selected != "" {
			ctx, err := locales.WithLocale(c.Request().Context(), language.Selected)
			if err == nil {
				c.SetRequest(c.Request().WithContext(ctx))
			}
		}
		return next(c)
	}
}

func (h *Handler) UpdateLanguage(c echo.Context) error {
	principal, err := h.currentPrincipal(c)
	if err != nil {
		return err
	}
	invalid := func() error {
		return echo.NewHTTPError(http.StatusBadRequest, i18n.T(c.Request().Context(), "account_language.invalid"))
	}
	r := c.Request()
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" || r.ContentLength > 8192 {
		return invalid()
	}
	r.Body = http.MaxBytesReader(c.Response(), r.Body, 8192)
	if err = r.ParseForm(); err != nil || len(r.PostForm.Encode()) > 8192 {
		return invalid()
	}
	for name, values := range r.PostForm {
		if len(values) != 1 || name != "locale" && name != "csrf" {
			return invalid()
		}
	}
	values, ok := r.PostForm["locale"]
	if !ok || len(values) != 1 || !preferences.ValidLanguage(values[0]) {
		return invalid()
	}
	if h.Preferences == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, i18n.T(c.Request().Context(), "account_language.unavailable"))
	}
	if err = h.Preferences.SetLanguage(c.Request().Context(), principal.UserID, values[0]); err != nil {
		if errors.Is(err, preferences.ErrNotFound) {
			return echo.NewHTTPError(http.StatusForbidden, i18n.T(c.Request().Context(), "account_language.account_unavailable"))
		}
		return echo.NewHTTPError(http.StatusServiceUnavailable, i18n.T(c.Request().Context(), "account_language.unavailable"))
	}
	h.SessionManager.Manager.Put(c.Request().Context(), "language_saved", true)
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.Redirect(http.StatusSeeOther, "/myaccount")
}
