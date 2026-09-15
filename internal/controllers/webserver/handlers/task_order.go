package handlers

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/profiles_views"
)

func taskOrderFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrTaskInvalid), errors.Is(err, inventory.ErrTagInvalid), errors.Is(err, inventory.ErrProfileInvalid):
		status, key = http.StatusBadRequest, "invalid"
	case errors.Is(err, inventory.ErrTaskOrderChanged):
		status, key = http.StatusConflict, "changed"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = http.StatusNotFound, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "denied"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "task_order."+key))
}

func (h *Handler) MoveTask(c echo.Context, up bool) error {
	from, err := tagID(c.Param("order"))
	if err != nil {
		return taskOrderFailure(c, err)
	}
	if !up && from == math.MaxInt64 {
		return taskOrderFailure(c, inventory.ErrTaskInvalid)
	}
	to := from + 1
	if up {
		to = from - 1
	}
	return h.reorderTask(c, from, to)
}

func (h *Handler) MoveTaskFromTo(c echo.Context) error {
	from, err := tagID(c.Param("from"))
	if err != nil {
		return taskOrderFailure(c, err)
	}
	to, err := tagID(c.Param("to"))
	if err != nil {
		return taskOrderFailure(c, err)
	}
	return h.reorderTask(c, from, to)
}

func (h *Handler) reorderTask(c echo.Context, from, to int64) error {
	if c.Request().Method != http.MethodPost {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	id, err := tagID(c.Param("id"))
	if err != nil {
		return taskOrderFailure(c, err)
	}
	if err = profileStatusForm(c); err != nil {
		return taskOrderFailure(c, inventory.ErrTaskInvalid)
	}
	size := 5
	if raw := c.FormValue("pageSize"); raw != "" {
		size, err = strconv.Atoi(raw)
		if err != nil || size <= 0 || size > 1000 || strconv.Itoa(size) != raw {
			return taskOrderFailure(c, inventory.ErrTaskInvalid)
		}
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return taskOrderFailure(c, err)
	}
	profileID, err := inventory.ReorderLegacyTask(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, id, from, to)
	if err != nil {
		return taskOrderFailure(c, err)
	}
	event, _ := json.Marshal(map[string]any{"profileTaskOrderSaved": map[string]any{"profileId": strconv.FormatInt(profileID, 10), "taskId": strconv.FormatInt(id, 10), "page": (to-1)/int64(size) + 1}})
	c.Response().Header().Set("HX-Trigger", string(event))
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) ProfileTaskList(c echo.Context) error {
	if c.Request().Method != http.MethodGet {
		return echo.NewHTTPError(http.StatusMethodNotAllowed)
	}
	id, err := tagID(c.Param("uuid"))
	if err != nil {
		return taskOrderFailure(c, err)
	}
	r := c.Request()
	if r.ContentLength != 0 || r.Header.Get("Content-Encoding") != "" || len(r.URL.RawQuery) > 8192 {
		return taskOrderFailure(c, inventory.ErrTaskInvalid)
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return taskOrderFailure(c, inventory.ErrTaskInvalid)
	}
	for key, v := range values {
		if len(v) != 1 || len(v[0]) > 128 {
			return taskOrderFailure(c, inventory.ErrTaskInvalid)
		}
		switch key {
		case "page", "pageSize", "sortBy", "sortOrder":
		default:
			return taskOrderFailure(c, inventory.ErrTaskInvalid)
		}
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	scope, err := legacyProfileScope(info)
	if err != nil {
		return taskOrderFailure(c, err)
	}
	defaultSize, err := h.Model.GetDefaultItemsPerPage()
	if err != nil {
		defaultSize = 5
	}
	page, size := 1, defaultSize
	for key, target := range map[string]*int{"page": &page, "pageSize": &size} {
		if raw := values.Get(key); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n <= 0 || strconv.Itoa(n) != raw {
				return taskOrderFailure(c, inventory.ErrTaskInvalid)
			}
			*target = n
		}
	}
	result, err := inventory.ReadLegacyTaskPage(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope, id, page, size)
	if err != nil {
		return taskOrderFailure(c, err)
	}
	p := partials.PaginationAndSort{CurrentPage: result.Page, PageSize: result.PageSize, NItems: result.Total, SortBy: values.Get("sortBy"), SortOrder: values.Get("sortOrder")}
	return RenderView(c, profiles_views.ProfileTaskList(c, p, int(id), result.Tasks, defaultSize, info))
}
