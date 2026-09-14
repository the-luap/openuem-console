package handlers

import (
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/nats/netbirdapi"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/computers_views"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

// Only group IDs may repeat. Input bounds cover the full provider selection;
// scalar aliases, duplicate identities, unknown fields and other encodings fail.
func netbirdRegistrationValues(c echo.Context, keys ...string) (url.Values, error) {
	r := c.Request()
	if r.Header.Get("Content-Encoding") != "" {
		return nil, inventory.ErrNetbirdOperationInvalid
	}
	var values url.Values
	var err error
	switch r.Method {
	case http.MethodGet:
		if r.ContentLength != 0 || len(r.URL.RawQuery) > 24<<10 {
			return nil, inventory.ErrNetbirdOperationInvalid
		}
		values, err = url.ParseQuery(r.URL.RawQuery)
	case http.MethodPost:
		media, _, parseErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if parseErr != nil || media != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" || r.ContentLength > 32<<10 {
			return nil, inventory.ErrNetbirdOperationInvalid
		}
		r.Body = http.MaxBytesReader(c.Response(), r.Body, 32<<10)
		err = r.ParseForm()
		values = r.PostForm
		keys = append(keys, "csrf", "confirmed")
		if values.Get("confirmed") != "yes" {
			return nil, inventory.ErrNetbirdOperationInvalid
		}
	default:
		return nil, inventory.ErrNetbirdOperationInvalid
	}
	if err != nil {
		return nil, inventory.ErrNetbirdOperationInvalid
	}
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	for key, list := range values {
		if !allowed[key] || len(list) == 0 || key != "group" && len(list) != 1 || key == "group" && len(list) > netbirdapi.MaxManagedGroups {
			return nil, inventory.ErrNetbirdOperationInvalid
		}
		seen := map[string]bool{}
		for _, value := range list {
			if len(value) > 256 || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
				return nil, inventory.ErrNetbirdOperationInvalid
			}
			if key == "group" && (len(value) > 128 || !inventory.ValidReportDeviceID(value) || seen[value]) {
				return nil, inventory.ErrNetbirdOperationInvalid
			}
			seen[value] = true
		}
	}
	if extra := values.Get("extra_dns"); extra != "" && extra != "yes" && extra != "no" {
		return nil, inventory.ErrNetbirdOperationInvalid
	}
	return values, nil
}

func (h *Handler) netbirdRegistrationInfo(c echo.Context) (*partials.CommonInfo, access.Scope, error) {
	info, scope, err := h.netbirdInfo(c)
	if err != nil {
		return nil, scope, err
	}
	if h.NetbirdRegistrations == nil {
		return nil, scope, netbirdFailure(inventory.ErrNetbirdOperationNotReady)
	}
	return info, scope, nil
}

func (h *Handler) NetbirdRegistrationChoices(c echo.Context) error {
	if _, err := netbirdRegistrationValues(c); err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdRegistrationInfo(c)
	if err != nil {
		return err
	}
	review, err := h.NetbirdRegistrations.Review(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), nil, false)
	if err != nil {
		return netbirdFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | NetBird registration", desktop_views.NetbirdRegistrationChoices(c, info, review), info))
}
func (h *Handler) NetbirdRegistrationReview(c echo.Context) error {
	values, err := netbirdRegistrationValues(c, "group", "extra_dns")
	if err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdRegistrationInfo(c)
	if err != nil {
		return err
	}
	review, err := h.NetbirdRegistrations.Review(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values["group"], values.Get("extra_dns") == "yes")
	if err != nil {
		return netbirdFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Review NetBird registration", desktop_views.NetbirdRegistrationReview(c, info, review, uuid.NewString()), info))
}
func (h *Handler) NetbirdRegistrationRequest(c echo.Context) error {
	values, err := netbirdRegistrationValues(c, "request_id", "revision", "group", "extra_dns")
	if err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdRegistrationInfo(c)
	if err != nil {
		return err
	}
	r, err := h.NetbirdRegistrations.Request(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("request_id"), values.Get("revision"), values["group"], values.Get("extra_dns") == "yes")
	if err != nil {
		return netbirdFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdRegistrationPath(info, r.DeviceID)+"/"+r.ID)
}
func (h *Handler) NetbirdRegistrationReceipt(c echo.Context) error {
	if _, err := netbirdRegistrationValues(c); err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdRegistrationInfo(c)
	if err != nil {
		return err
	}
	r, err := h.NetbirdRegistrations.Read(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"))
	if err != nil {
		return netbirdFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | NetBird registration receipt", desktop_views.NetbirdRegistrationReceipt(c, info, r), info))
}
func (h *Handler) NetbirdRegistrationHistory(c echo.Context) error {
	values, err := netbirdRegistrationValues(c, "before")
	if err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdRegistrationInfo(c)
	if err != nil {
		return err
	}
	rows, err := h.NetbirdRegistrations.History(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("before"))
	if err != nil {
		return netbirdFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | NetBird registration history", desktop_views.NetbirdRegistrationHistory(c, info, c.Param("uuid"), rows), info))
}
func (h *Handler) NetbirdRegistrationCancel(c echo.Context) error {
	if _, err := netbirdRegistrationValues(c); err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdRegistrationInfo(c)
	if err != nil {
		return err
	}
	if err = h.NetbirdRegistrations.Cancel(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request")); err != nil {
		return netbirdFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdRegistrationPath(info, c.Param("uuid"))+"/"+c.Param("request"))
}
func (h *Handler) NetbirdRegistrationCleanup(c echo.Context) error {
	if _, err := netbirdRegistrationValues(c); err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdRegistrationInfo(c)
	if err != nil {
		return err
	}
	if _, err = h.NetbirdRegistrations.ReconcileCleanup(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request")); err != nil {
		return netbirdFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdRegistrationPath(info, c.Param("uuid"))+"/"+c.Param("request"))
}

func (h *Handler) NetbirdCleanupReview(c echo.Context) error {
	if _, err := netbirdRegistrationValues(c); err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdRegistrationInfo(c)
	if err != nil {
		return err
	}
	v, err := h.NetbirdRegistrations.ReviewCleanup(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"))
	if err != nil {
		return netbirdFailure(err)
	}
	return RenderView(c, computers_views.InventoryIndex(" | Review NetBird key removal", desktop_views.NetbirdCleanupReview(c, info, v, uuid.NewString()), info))
}

func (h *Handler) NetbirdCleanupRetry(c echo.Context) error {
	values, err := netbirdRegistrationValues(c, "retry_id", "revision")
	if err != nil {
		return netbirdFailure(err)
	}
	info, scope, err := h.netbirdRegistrationInfo(c)
	if err != nil {
		return err
	}
	_, err = h.NetbirdRegistrations.RetryCleanup(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"), values.Get("retry_id"), values.Get("revision"))
	if err != nil {
		return netbirdFailure(err)
	}
	return netbirdRedirect(c, desktop_views.NetbirdRegistrationPath(info, c.Param("uuid"))+"/"+c.Param("request")+"/cleanup/review")
}
