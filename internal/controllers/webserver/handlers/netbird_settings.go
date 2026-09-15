package handlers

import (
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
	consolesettings "github.com/open-uem/openuem-console/internal/settings"
	"github.com/open-uem/openuem-console/internal/views/admin_views"
)

func netbirdSettingsFailure(err error) error {
	status, message := http.StatusServiceUnavailable, "NetBird settings are unavailable. Reload before trying again."
	switch {
	case errors.Is(err, access.ErrDenied):
		status, message = http.StatusForbidden, "Only current server administrators can manage NetBird settings."
	case errors.Is(err, consolesettings.ErrNetbirdInvalid):
		status, message = http.StatusBadRequest, "Invalid NetBird request. Check the HTTPS URL and explicit token action."
	case errors.Is(err, consolesettings.ErrNetbirdMissing):
		status, message = http.StatusNotFound, "The NetBird organization was not found."
	case errors.Is(err, consolesettings.ErrNetbirdConflict):
		status, message = http.StatusConflict, "NetBird settings changed or cannot be safely edited. Reload before continuing."
	case errors.Is(err, consolesettings.ErrNetbirdSecret):
		message = "The NetBird token could not be securely stored or read. Verify the configured encryption key."
	}
	return echo.NewHTTPError(status, message)
}

func netbirdSettingsForm(c echo.Context) (url.Values, error) {
	r := c.Request()
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Encoding") != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return nil, consolesettings.ErrNetbirdInvalid
	}
	if r.ContentLength > 64<<10 {
		return nil, echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Form is too large")
	}
	r.Body = http.MaxBytesReader(c.Response(), r.Body, 64<<10)
	if err = r.ParseForm(); err != nil {
		return nil, consolesettings.ErrNetbirdInvalid
	}
	if len(r.PostForm.Encode()) > 64<<10 {
		return nil, consolesettings.ErrNetbirdInvalid
	}
	for key, values := range r.PostForm {
		if len(values) != 1 || !utf8.ValidString(values[0]) || strings.ContainsRune(values[0], 0) {
			return nil, consolesettings.ErrNetbirdInvalid
		}
		max := 128
		switch key {
		case "csrf", "settingsId", "revision", "token-action":
		case "management-url":
			max = 2048
		case "token":
			max = 16384
		default:
			return nil, consolesettings.ErrNetbirdInvalid
		}
		if len(values[0]) > max {
			return nil, consolesettings.ErrNetbirdInvalid
		}
	}
	return r.PostForm, nil
}

func (h *Handler) NetbirdSettings(c echo.Context) error {
	r := c.Request()
	c.Response().Header().Set("Cache-Control", "no-store")
	raw := c.Param("tenant")
	id, err := strconv.Atoi(raw)
	if err != nil || id <= 0 || strconv.Itoa(id) != raw || c.Param("site") != "" {
		return netbirdSettingsFailure(consolesettings.ErrNetbirdInvalid)
	}
	scope := access.Scope{TenantID: id}
	base := "/tenant/" + raw + "/admin/netbird"
	values := url.Values{}
	switch r.Method {
	case http.MethodGet:
		if r.ContentLength != 0 || r.Header.Get("Content-Encoding") != "" || r.URL.ForceQuery || len(r.URL.RawQuery) > 64 {
			return netbirdSettingsFailure(consolesettings.ErrNetbirdInvalid)
		}
		values, err = url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return netbirdSettingsFailure(consolesettings.ErrNetbirdInvalid)
		}
		for key, v := range values {
			if key != "saved" || len(v) != 1 || v[0] != "1" {
				return netbirdSettingsFailure(consolesettings.ErrNetbirdInvalid)
			}
		}
	case http.MethodPost:
		values, err = netbirdSettingsForm(c)
		if err != nil {
			var httpError *echo.HTTPError
			if errors.As(err, &httpError) {
				return err
			}
			return netbirdSettingsFailure(err)
		}
	default:
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	info.TenantID = raw
	store, err := consolesettings.NewNetbirdStore(h.Model.DB, h.Access, h.EncryptionMasterKey)
	if err != nil {
		return netbirdSettingsFailure(err)
	}
	if r.Method == http.MethodPost {
		settingsID, err := strconv.ParseInt(values.Get("settingsId"), 10, 64)
		if err != nil || settingsID < 0 || strconv.FormatInt(settingsID, 10) != values.Get("settingsId") {
			return netbirdSettingsFailure(consolesettings.ErrNetbirdInvalid)
		}
		if err = store.Save(r.Context(), info.Principal.UserID, scope, settingsID, values.Get("revision"), values.Get("management-url"), values.Get("token-action"), values.Get("token")); err != nil {
			return netbirdSettingsFailure(err)
		}
		return smtpRedirect(c, base+"?saved=1")
	}
	review, err := store.Read(r.Context(), info.Principal.UserID, scope)
	if err != nil {
		return netbirdSettingsFailure(err)
	}
	return RenderView(c, admin_views.NetbirdSettingsIndex(" | NetBird settings", admin_views.NetbirdSettings(c, review, info, base, values.Get("saved") == "1"), info))
}
