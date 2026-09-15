package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func metadataCapability(method, path string) (access.Capability, bool) {
	if method != http.MethodGet && method != http.MethodPost {
		return "", false
	}
	switch path {
	case "/tenant/:tenant/admin/metadata":
		return access.ManageMetadata, method == http.MethodGet
	case "/tenant/:tenant/admin/metadata/new", "/tenant/:tenant/admin/metadata/:field", "/tenant/:tenant/admin/metadata/:field/deletion/:review":
		return access.ManageMetadata, true
	case "/tenant/:tenant/admin/metadata/:field/deletion":
		return access.ManageMetadata, method == http.MethodPost
	}
	return "", false
}
func metadataFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, inventory.ErrMetadataInvalid), errors.Is(err, inventory.ErrReportFilter):
		status, key = 400, "invalid"
	case errors.Is(err, inventory.ErrMetadataConflict):
		status, key = 409, "conflict"
	case errors.Is(err, inventory.ErrMetadataNameUnavailable):
		status, key = 409, "name_unavailable"
	case errors.Is(err, inventory.ErrMetadataUnsafeReferences):
		status, key = 409, "unsafe_references"
	case errors.Is(err, inventory.ErrNotFound):
		status, key = 404, "not_found"
	case errors.Is(err, access.ErrDenied):
		status, key = 403, "denied"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "custom_metadata."+key))
}
func (h *Handler) metadataInfo(c echo.Context) (*partials.CommonInfo, access.Scope, error) {
	c.Response().Header().Set("Cache-Control", "no-store")
	tenant, err := metadataID(c.Param("tenant"))
	if err != nil || c.Param("site") != "" {
		return nil, access.Scope{}, metadataFailure(c, inventory.ErrNotFound)
	}
	scope := access.Scope{TenantID: tenant}
	p, err := h.currentPrincipal(c)
	if err != nil {
		return nil, scope, err
	}
	cap, ok := metadataCapability(c.Request().Method, c.Path())
	if !ok || !p.Can(cap, scope) {
		return nil, scope, metadataFailure(c, access.ErrDenied)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return nil, scope, err
	}
	if info.TenantID != c.Param("tenant") {
		return nil, scope, metadataFailure(c, inventory.ErrNotFound)
	}
	info.SiteID = "-1"
	visible := info.Tenants[:0]
	for _, tenant := range info.Tenants {
		if p.Can(access.ReadDevices, access.Scope{TenantID: tenant.ID}) {
			visible = append(visible, tenant)
		}
	}
	info.Tenants = visible
	return info, scope, nil
}
func metadataID(raw string) (int, error) {
	id, err := strconv.Atoi(raw)
	if err != nil || id <= 0 || strconv.Itoa(id) != raw {
		return 0, inventory.ErrMetadataInvalid
	}
	return id, nil
}
func metadataForm(c echo.Context, required ...string) (url.Values, error) {
	allowed := append([]string{"csrf"}, required...)
	f, err := boundedDeviceManagementForm(c, "custom_metadata.invalid", allowed, 64<<10)
	if err != nil {
		return nil, err
	}
	for _, key := range required {
		if len(f[key]) != 1 {
			return nil, metadataFailure(c, inventory.ErrMetadataInvalid)
		}
	}
	return f, nil
}
func metadataNoQuery(c echo.Context) error {
	if c.Request().URL.RawQuery != "" || c.Request().URL.ForceQuery {
		return metadataFailure(c, inventory.ErrMetadataInvalid)
	}
	return nil
}
func (h *Handler) MetadataLegacyMutation(c echo.Context) error {
	return echo.NewHTTPError(http.StatusMethodNotAllowed)
}

func (h *Handler) MetadataFields(c echo.Context) error {
	info, scope, err := h.metadataInfo(c)
	if err != nil {
		return err
	}
	filter, err := desktopReportFilter(c.Request().URL.RawQuery)
	if err != nil {
		return metadataFailure(c, err)
	}
	page, err := inventory.ListMetadataFields(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope.TenantID, filter.Search, int(filter.After))
	if err != nil {
		return metadataFailure(c, err)
	}
	return renderApple(c, desktop_views.MetadataFields(c, info, page, filter.Search, int(filter.After)))
}
func (h *Handler) MetadataField(c echo.Context) error {
	info, scope, err := h.metadataInfo(c)
	if err != nil {
		return err
	}
	if err = metadataNoQuery(c); err != nil {
		return err
	}
	id := 0
	if c.Param("field") != "" {
		id, err = metadataID(c.Param("field"))
		if err != nil {
			return metadataFailure(c, err)
		}
	}
	ctx := c.Request().Context()
	data := &inventory.MetadataField{TenantID: scope.TenantID}
	draft := *data
	message := ""
	if c.Request().Method == http.MethodPost {
		f, e := metadataForm(c, "revision", "name", "description")
		if e != nil {
			return e
		}
		draft.Name, draft.Description = f.Get("name"), f.Get("description")
		data, err = inventory.SaveMetadataField(ctx, h.Model.DB, h.Access, info.Principal.UserID, scope.TenantID, id, f.Get("revision"), draft.Name, draft.Description)
		if errors.Is(err, inventory.ErrMetadataConflict) || errors.Is(err, inventory.ErrMetadataNameUnavailable) {
			key := "conflict"
			if errors.Is(err, inventory.ErrMetadataNameUnavailable) {
				key = "name_unavailable"
			}
			if id > 0 {
				data, err = inventory.ReadMetadataField(ctx, h.Model.DB, h.Access, info.Principal.UserID, scope.TenantID, id)
			} else {
				data = &inventory.MetadataField{TenantID: scope.TenantID}
				err = nil
			}
			message = i18n.T(ctx, "custom_metadata."+key)
			c.Response().Status = http.StatusConflict
		} else if err == nil {
			return c.Redirect(303, desktop_views.MetadataFieldsPath(info)+"/"+strconv.Itoa(data.ID))
		}
	} else if id > 0 {
		data, err = inventory.ReadMetadataField(ctx, h.Model.DB, h.Access, info.Principal.UserID, scope.TenantID, id)
		if err == nil {
			draft = *data
		}
	}
	if err != nil {
		return metadataFailure(c, err)
	}
	return renderApple(c, desktop_views.MetadataField(c, info, data, draft, message))
}
func (h *Handler) MetadataDeletionReview(c echo.Context) error {
	info, scope, err := h.metadataInfo(c)
	if err != nil {
		return err
	}
	id, err := metadataID(c.Param("field"))
	if err != nil {
		return metadataFailure(c, err)
	}
	f, err := metadataForm(c, "revision")
	if err != nil {
		return err
	}
	review, err := inventory.ReviewMetadataDeletion(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope.TenantID, id, f.Get("revision"))
	if err != nil {
		return metadataFailure(c, err)
	}
	return c.Redirect(303, desktop_views.MetadataFieldsPath(info)+"/"+strconv.Itoa(id)+"/deletion/"+review.ID)
}
func (h *Handler) MetadataDeletionReceipt(c echo.Context) error {
	info, scope, err := h.metadataInfo(c)
	if err != nil {
		return err
	}
	id, err := metadataID(c.Param("field"))
	if err != nil {
		return metadataFailure(c, err)
	}
	commit := c.Request().Method == http.MethodPost
	if commit {
		f, err := metadataForm(c, "confirm")
		if err != nil {
			return err
		}
		if f.Get("confirm") != "delete" {
			return metadataFailure(c, inventory.ErrMetadataInvalid)
		}
	} else if err = metadataNoQuery(c); err != nil {
		return err
	}
	review, err := inventory.MetadataDeletionReceipt(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope.TenantID, id, c.Param("review"), commit)
	message := ""
	if errors.Is(err, inventory.ErrMetadataConflict) || errors.Is(err, inventory.ErrMetadataUnsafeReferences) {
		key := "deletion_changed"
		if errors.Is(err, inventory.ErrMetadataUnsafeReferences) {
			key = "unsafe_references"
		}
		review, err = inventory.MetadataDeletionReceipt(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, scope.TenantID, id, c.Param("review"), false)
		message = i18n.T(c.Request().Context(), "custom_metadata."+key)
		c.Response().Status = 409
	} else if err == nil && commit {
		return c.Redirect(303, desktop_views.MetadataFieldsPath(info)+"/"+strconv.Itoa(id)+"/deletion/"+review.ID)
	}
	if err != nil {
		return metadataFailure(c, err)
	}
	return renderApple(c, desktop_views.MetadataDeletion(c, info, review, message))
}
func (h *Handler) DesktopMetadata(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	info, selected, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	filter, err := desktopReportFilter(c.Request().URL.RawQuery)
	if err != nil {
		return metadataFailure(c, err)
	}
	page, err := inventory.ListDeviceMetadata(c.Request().Context(), h.Model.DB, h.Access, info.Principal.UserID, access.Scope{TenantID: selected.TenantID, SiteID: selected.SiteID}, c.Param("uuid"), filter.Search, int(filter.After))
	if err != nil {
		return metadataFailure(c, err)
	}
	return renderApple(c, desktop_views.DeviceMetadata(c, info, page, filter.Search, int(filter.After)))
}
func (h *Handler) DesktopMetadataValue(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	info, selected, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	if err = metadataNoQuery(c); err != nil {
		return err
	}
	field, err := metadataID(c.Param("field"))
	if err != nil {
		return metadataFailure(c, err)
	}
	ctx := c.Request().Context()
	scope := access.Scope{TenantID: selected.TenantID, SiteID: selected.SiteID}
	id := c.Param("uuid")
	var data *inventory.MetadataValue
	draft, message := "", ""
	if c.Request().Method == http.MethodPost {
		clear := appleRoute(c.Path()) == "/computers/:uuid/metadata/:field/clear"
		fields := []string{"field_revision", "revision", "value"}
		if clear {
			fields = []string{"field_revision", "revision", "confirm"}
		}
		f, e := metadataForm(c, fields...)
		if e != nil {
			return e
		}
		if clear && f.Get("confirm") != "clear" {
			return metadataFailure(c, inventory.ErrMetadataInvalid)
		}
		draft = f.Get("value")
		data, err = inventory.SaveMetadataValue(ctx, h.Model.DB, h.Access, info.Principal.UserID, scope, id, field, f.Get("field_revision"), f.Get("revision"), draft, clear)
		if errors.Is(err, inventory.ErrMetadataConflict) {
			data, err = inventory.ReadMetadataValue(ctx, h.Model.DB, h.Access, info.Principal.UserID, scope, id, field)
			key := "conflict"
			if clear {
				key = "clear_conflict"
				if err == nil {
					draft = data.Value
				}
			}
			message = i18n.T(ctx, "custom_metadata."+key)
			c.Response().Status = 409
		} else if err == nil {
			return c.Redirect(303, desktop_views.MetadataValuePath(info, id, field))
		}
	} else {
		data, err = inventory.ReadMetadataValue(ctx, h.Model.DB, h.Access, info.Principal.UserID, scope, id, field)
		if err == nil {
			draft = data.Value
		}
	}
	if err != nil {
		return metadataFailure(c, err)
	}
	return renderApple(c, desktop_views.MetadataValue(c, info, data, draft, message))
}
