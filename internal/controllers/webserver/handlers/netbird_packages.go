package handlers

import (
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/admin_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func netbirdPackageCapability(method, path string) (access.Capability, bool) {
	switch path {
	case "/tenant/:tenant/netbird/packages":
		if method == http.MethodGet {
			return access.ReadSoftware, true
		}
		if method == http.MethodPost {
			return access.ManageSoftware, true
		}
	case "/tenant/:tenant/netbird/packages/new":
		if method == http.MethodGet {
			return access.ManageSoftware, true
		}
	case "/tenant/:tenant/netbird/packages/:approval":
		if method == http.MethodGet {
			return access.ReadSoftware, true
		}
	case "/tenant/:tenant/netbird/packages/:approval/revoke":
		if method == http.MethodPost {
			return access.ManageSoftware, true
		}
	}
	return "", false
}

func netbirdPackageFailure(err error) error {
	status, message := http.StatusServiceUnavailable, "NetBird package approvals are unavailable. Reload before trying again."
	switch {
	case errors.Is(err, access.ErrDenied):
		status, message = http.StatusForbidden, "You do not have the required software permission for this organization."
	case errors.Is(err, inventory.ErrNetbirdPackageInvalid):
		status, message = http.StatusBadRequest, "Invalid package approval. Check the exact package target, native version, HTTPS source, size, SHA-256 and confirmation."
	case errors.Is(err, inventory.ErrNetbirdPackageMissing):
		status, message = http.StatusNotFound, "The package approval was not found in this organization."
	case errors.Is(err, inventory.ErrNetbirdPackageConflict):
		status, message = http.StatusConflict, "The package approval does not match this request. Reload before continuing."
	case errors.Is(err, inventory.ErrNetbirdPackageSecret):
		message = "The package source could not be securely stored or authenticated. Verify the configured encryption key."
	}
	return echo.NewHTTPError(status, message)
}

func (h *Handler) netbirdPackageInfo(c echo.Context) (*partials.CommonInfo, access.Scope, *inventory.NetbirdPackageStore, error) {
	c.Response().Header().Set("Cache-Control", "no-store")
	id, err := strconv.Atoi(c.Param("tenant"))
	if err != nil || id <= 0 || strconv.Itoa(id) != c.Param("tenant") || c.Param("site") != "" {
		return nil, access.Scope{}, nil, netbirdPackageFailure(inventory.ErrNetbirdPackageInvalid)
	}
	scope := access.Scope{TenantID: id}
	p, err := h.currentPrincipal(c)
	if err != nil {
		return nil, scope, nil, err
	}
	capability, ok := netbirdPackageCapability(c.Request().Method, c.Path())
	if !ok || !p.Can(capability, scope) {
		return nil, scope, nil, netbirdPackageFailure(access.ErrDenied)
	}
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return nil, scope, nil, err
	}
	if info.TenantID != c.Param("tenant") {
		return nil, scope, nil, netbirdPackageFailure(inventory.ErrNetbirdPackageMissing)
	}
	info.SiteID = "-1"
	visible := info.Tenants[:0]
	for _, tenant := range info.Tenants {
		if p.Can(access.ReadSoftware, access.Scope{TenantID: tenant.ID}) {
			visible = append(visible, tenant)
		}
	}
	info.Tenants = visible
	store, err := inventory.NewNetbirdPackageStore(h.Model.DB, h.Access, h.EncryptionMasterKey)
	if err != nil {
		return nil, scope, nil, netbirdPackageFailure(err)
	}
	return info, scope, store, nil
}

func netbirdPackageValues(c echo.Context, keys ...string) (url.Values, error) {
	r := c.Request()
	if r.URL.ForceQuery || r.Header.Get("Content-Encoding") != "" {
		return nil, inventory.ErrNetbirdPackageInvalid
	}
	var values url.Values
	var err error
	if r.Method == http.MethodGet {
		if r.ContentLength != 0 || len(r.URL.RawQuery) > 256 {
			return nil, inventory.ErrNetbirdPackageInvalid
		}
		values, err = url.ParseQuery(r.URL.RawQuery)
	} else if r.Method == http.MethodPost {
		media, _, parseErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if parseErr != nil || media != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 || r.URL.RawQuery != "" || r.ContentLength > 16<<10 {
			return nil, inventory.ErrNetbirdPackageInvalid
		}
		r.Body = http.MaxBytesReader(c.Response(), r.Body, 16<<10)
		err = r.ParseForm()
		values = r.PostForm
		keys = append(keys, "csrf", "confirmed")
		if values.Get("confirmed") != "yes" {
			return nil, inventory.ErrNetbirdPackageInvalid
		}
	} else {
		return nil, inventory.ErrNetbirdPackageInvalid
	}
	if err != nil {
		return nil, inventory.ErrNetbirdPackageInvalid
	}
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	for key, v := range values {
		limit := 128
		if key == "source_url" {
			limit = 2048
		}
		if key == "verification" {
			limit = 512
		}
		if !allowed[key] || len(v) != 1 || len(v[0]) > limit || !utf8.ValidString(v[0]) || strings.ContainsRune(v[0], 0) {
			return nil, inventory.ErrNetbirdPackageInvalid
		}
	}
	return values, nil
}

func (h *Handler) NetbirdPackages(c echo.Context) error {
	v, err := netbirdPackageValues(c, "after")
	if err != nil {
		return netbirdPackageFailure(err)
	}
	info, scope, store, err := h.netbirdPackageInfo(c)
	if err != nil {
		return err
	}
	page, err := store.List(c.Request().Context(), info.Principal.UserID, scope, v.Get("after"))
	if err != nil {
		return netbirdPackageFailure(err)
	}
	return RenderView(c, admin_views.NetbirdSettingsIndex(" | NetBird packages", admin_views.NetbirdPackageList(c, info, page), info))
}

func (h *Handler) NewNetbirdPackage(c echo.Context) error {
	if _, err := netbirdPackageValues(c); err != nil {
		return netbirdPackageFailure(err)
	}
	info, _, _, err := h.netbirdPackageInfo(c)
	if err != nil {
		return err
	}
	return RenderView(c, admin_views.NetbirdSettingsIndex(" | Approve NetBird package", admin_views.NetbirdPackageNew(c, info, uuid.NewString()), info))
}

func (h *Handler) ApproveNetbirdPackage(c echo.Context) error {
	v, err := netbirdPackageValues(c, "approval_id", "target", "version", "source_url", "size", "sha256", "verification")
	if err != nil {
		return netbirdPackageFailure(err)
	}
	info, scope, store, err := h.netbirdPackageInfo(c)
	if err != nil {
		return err
	}
	target := strings.Split(v.Get("target"), "/")
	if len(target) != 3 {
		return netbirdPackageFailure(inventory.ErrNetbirdPackageInvalid)
	}
	size, err := strconv.ParseInt(v.Get("size"), 10, 64)
	if err != nil || strconv.FormatInt(size, 10) != v.Get("size") {
		return netbirdPackageFailure(inventory.ErrNetbirdPackageInvalid)
	}
	p := packageapi.Package{Schema: packageapi.Schema, ApprovalID: v.Get("approval_id"), TenantID: int64(scope.TenantID), Platform: target[0], Architecture: target[1], Format: target[2], PackageID: "netbird", Version: v.Get("version"), URL: v.Get("source_url"), Size: size, SHA256: v.Get("sha256")}
	if p.Platform == "macos" {
		p.PackageID = "io.netbird.client"
	}
	approved, err := store.Approve(c.Request().Context(), info.Principal.UserID, scope, p, v.Get("verification"))
	if err != nil {
		return netbirdPackageFailure(err)
	}
	return smtpRedirect(c, admin_views.NetbirdPackageBase(info)+"/"+approved.ID)
}

func (h *Handler) NetbirdPackage(c echo.Context) error {
	if _, err := netbirdPackageValues(c); err != nil {
		return netbirdPackageFailure(err)
	}
	info, scope, store, err := h.netbirdPackageInfo(c)
	if err != nil {
		return err
	}
	p, err := store.Read(c.Request().Context(), info.Principal.UserID, scope, c.Param("approval"))
	if err != nil {
		return netbirdPackageFailure(err)
	}
	return RenderView(c, admin_views.NetbirdSettingsIndex(" | NetBird package approval", admin_views.NetbirdPackageDetail(c, info, p, uuid.NewString()), info))
}

func (h *Handler) RevokeNetbirdPackage(c echo.Context) error {
	v, err := netbirdPackageValues(c, "request_id", "digest")
	if err != nil {
		return netbirdPackageFailure(err)
	}
	info, scope, store, err := h.netbirdPackageInfo(c)
	if err != nil {
		return err
	}
	p, err := store.Revoke(c.Request().Context(), info.Principal.UserID, scope, c.Param("approval"), v.Get("digest"), v.Get("request_id"))
	if err != nil {
		return netbirdPackageFailure(err)
	}
	return smtpRedirect(c, admin_views.NetbirdPackageBase(info)+"/"+p.ID)
}
