package handlers

import (
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/computers_views"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func manualQuery(c echo.Context, review bool) (url.Values, error) {
	r := c.Request()
	if r.Method != http.MethodGet || r.ContentLength != 0 || r.Header.Get("Content-Encoding") != "" || len(r.URL.RawQuery) > 2048 {
		return nil, inventory.ErrManualInvalid
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, inventory.ErrManualInvalid
	}
	for key, v := range values {
		if len(v) != 1 || len(v[0]) > 256 || !utf8.ValidString(v[0]) || strings.ContainsRune(v[0], 0) {
			return nil, inventory.ErrManualInvalid
		}
		if key != "kind" && key != "q" && !(review && key == "source_id") {
			return nil, inventory.ErrManualInvalid
		}
	}
	if values.Get("kind") == "" {
		values.Set("kind", "task")
	}
	if values.Get("kind") != "task" && values.Get("kind") != "profile" {
		return nil, inventory.ErrManualInvalid
	}
	return values, nil
}

func (h *Handler) manualInfo(c echo.Context) (*partials.CommonInfo, access.Scope, error) {
	c.Response().Header().Set("Cache-Control", "no-store")
	info, scope, err := h.desktopInfo(c)
	if err != nil {
		return nil, access.Scope{}, err
	}
	if scope.SiteID <= 0 {
		return nil, access.Scope{}, manualFailure(c, inventory.ErrManualInvalid)
	}
	if h.ManualExecution == nil {
		return nil, access.Scope{}, manualFailure(c, inventory.ErrRefreshNotReady)
	}
	return info, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}, nil
}

func (h *Handler) DesktopExecutionChoices(c echo.Context) error {
	values, err := manualQuery(c, false)
	if err != nil {
		return manualFailure(c, err)
	}
	info, scope, err := h.manualInfo(c)
	if err != nil {
		return err
	}
	page, err := h.ManualExecution.Choices(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("kind"), values.Get("q"))
	if err != nil {
		return manualFailure(c, err)
	}
	return RenderView(c, computers_views.InventoryIndex("| Manual execution", desktop_views.ManualChoices(c, info, page), info))
}

func (h *Handler) DesktopExecutionReview(c echo.Context) error {
	values, err := manualQuery(c, true)
	if err != nil {
		return manualFailure(c, err)
	}
	id, err := tagID(values.Get("source_id"))
	if err != nil {
		return manualFailure(c, inventory.ErrManualInvalid)
	}
	info, scope, err := h.manualInfo(c)
	if err != nil {
		return err
	}
	review, err := h.ManualExecution.Review(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("kind"), id)
	if err != nil {
		return manualFailure(c, err)
	}
	return RenderView(c, computers_views.InventoryIndex("| Confirm manual execution", desktop_views.ManualReview(c, info, review, uuid.NewString(), values.Get("q")), info))
}

func readManualForm(c echo.Context) (url.Values, error) {
	r := c.Request()
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.Header.Get("Content-Encoding") != "" || r.ContentLength > 8<<10 {
		return nil, inventory.ErrManualInvalid
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		return nil, inventory.ErrManualInvalid
	}
	r.Body = http.MaxBytesReader(c.Response(), r.Body, 8<<10)
	if err = r.ParseForm(); err != nil || len(r.PostForm.Encode()) > 8<<10 {
		return nil, inventory.ErrManualInvalid
	}
	for key, v := range r.PostForm {
		if len(v) != 1 {
			return nil, inventory.ErrManualInvalid
		}
		switch key {
		case "csrf", "request_id", "kind", "source_id", "revision", "confirmed":
		default:
			return nil, inventory.ErrManualInvalid
		}
	}
	if r.PostForm.Get("confirmed") != "yes" {
		return nil, inventory.ErrManualInvalid
	}
	return r.PostForm, nil
}

func (h *Handler) DesktopExecutionRequest(c echo.Context) error { return h.manualRequest(c, "") }

func (h *Handler) manualRequest(c echo.Context, expectedKind string) error {
	values, err := readManualForm(c)
	if err != nil {
		return manualFailure(c, err)
	}
	if expectedKind != "" && values.Get("kind") != expectedKind {
		return manualFailure(c, inventory.ErrManualInvalid)
	}
	id, err := tagID(values.Get("source_id"))
	if err != nil {
		return manualFailure(c, inventory.ErrManualInvalid)
	}
	info, scope, err := h.manualInfo(c)
	if err != nil {
		return err
	}
	request, err := h.ManualExecution.Request(c.Request().Context(), info.Principal.UserID, scope, c.Param("uuid"), values.Get("request_id"), values.Get("kind"), id, values.Get("revision"))
	if err != nil {
		return manualFailure(c, err)
	}
	location := partials.GetNavigationUrl(info, "/computers/"+url.PathEscape(request.DeviceID)+"/execution/"+request.ID)
	// The intent and audit have committed. Do not make success depend on another
	// database read or a full inventory render after admission.
	if c.Request().Header.Get("HX-Request") == "true" {
		c.Response().Header().Set("HX-Redirect", location)
		return c.NoContent(http.StatusNoContent)
	}
	return c.Redirect(http.StatusSeeOther, location)
}

func (h *Handler) DesktopExecutionReceipt(c echo.Context) error {
	r := c.Request()
	if r.Method != http.MethodGet || r.ContentLength != 0 || r.URL.RawQuery != "" || r.Header.Get("Content-Encoding") != "" {
		return manualFailure(c, inventory.ErrManualInvalid)
	}
	info, scope, err := h.manualInfo(c)
	if err != nil {
		return err
	}
	request, err := h.ManualExecution.Read(r.Context(), info.Principal.UserID, scope, c.Param("uuid"), c.Param("request"))
	if err != nil {
		return manualFailure(c, err)
	}
	return RenderView(c, computers_views.InventoryIndex("| Manual execution receipt", desktop_views.ManualReceipt(c, info, request), info))
}

func manualFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "denied"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, inventory.ErrManualInvalid):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrManualChanged):
		status, key = http.StatusConflict, "changed"
	case errors.Is(err, inventory.ErrManualConflict):
		status, key = http.StatusConflict, "conflict"
	case errors.Is(err, inventory.ErrManualUnsupported):
		status, key = http.StatusUnprocessableEntity, "unsupported"
	case errors.Is(err, inventory.ErrRefreshNotReady):
		key = "not_ready"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "manual_execution."+key))
}
