package handlers

import (
	"crypto/subtle"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/open-uem/openuem-console/internal/views/audit_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func (h *Handler) RegisterAudit(e *echo.Echo) {
	for _, prefix := range []string{"", "/tenant/:tenant", "/tenant/:tenant/site/:site"} {
		g := e.Group(prefix, h.IsAuthenticated, h.AuditCSRF)
		g.GET("/audit", h.AuditLog)
		g.POST("/audit/export", h.AuditExport)
		if !strings.Contains(prefix, "/site/") {
			g.GET("/audit/retention", h.AuditRetention)
			g.POST("/audit/retention/preview", h.AuditRetentionPreview)
			g.POST("/audit/retention/apply", h.AuditRetentionApply)
		}
	}
}

func auditCapability(method, path string) (access.Capability, bool) {
	path = appleRoute(path)
	if method == http.MethodGet && (path == "/audit" || path == "/audit/retention") || method == http.MethodPost && path == "/audit/export" {
		return access.ReadAudit, true
	}
	if method == http.MethodPost && (path == "/audit/retention/preview" || path == "/audit/retention/apply") {
		return access.ManageAuditRetention, true
	}
	return "", false
}

// Export and retention forms never merge query parameters into their body.
func (h *Handler) AuditCSRF(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set("Cache-Control", "no-store")
		c.Response().Header().Set("X-Content-Type-Options", "nosniff")
		if c.Request().Method == http.MethodPost {
			if c.Request().ContentLength > 16384 {
				return echo.NewHTTPError(400, "Invalid or oversized audit form")
			}
			typeName, _, err := mime.ParseMediaType(c.Request().Header.Get("Content-Type"))
			if err != nil || typeName != "application/x-www-form-urlencoded" {
				return echo.NewHTTPError(415, "Use a URL-encoded form")
			}
			c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, 16384)
			if err = c.Request().ParseForm(); err != nil {
				return echo.NewHTTPError(400, "Invalid or oversized audit form")
			}
			// The common CSRF middleware may have parsed the body already.
			if len(c.Request().PostForm.Encode()) > 16384 {
				return echo.NewHTTPError(400, "Invalid or oversized audit form")
			}
			token := c.Request().PostForm["csrf"]
			expected, _ := c.Get("csrf").(string)
			if len(token) != 1 || expected == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(token[0])) != 1 {
				return echo.NewHTTPError(403, "Invalid CSRF token")
			}
		}
		return next(c)
	}
}

func auditFailure(err error) error {
	switch {
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(403, "Permission denied for this audit scope")
	case errors.Is(err, audit.ErrInvalid):
		return echo.NewHTTPError(400, "Invalid audit filter or retention request")
	case errors.Is(err, audit.ErrConflict):
		return echo.NewHTTPError(409, "The preview expired, was used, or the policy changed. Create a new preview.")
	case errors.Is(err, audit.ErrTooLarge):
		return echo.NewHTTPError(422, "The export exceeds 10,000 events or 16 MiB. Narrow the time range or filters.")
	case errors.Is(err, audit.ErrBusy):
		return echo.NewHTTPError(429, "Audit exports are busy. Try again shortly.")
	default:
		return echo.NewHTTPError(503, "Unable to read or update the audit log. Try again shortly.")
	}
}

func (h *Handler) auditScope(c echo.Context) (access.Scope, error) {
	var scope access.Scope
	for i, name := range []string{"tenant", "site"} {
		if value := c.Param(name); value != "" {
			id, err := strconv.Atoi(value)
			if err != nil || id <= 0 || strconv.Itoa(id) != value {
				return scope, echo.NewHTTPError(404, "Audit scope not found")
			}
			if i == 0 {
				scope.TenantID = id
			} else {
				scope.SiteID = id
			}
		}
	}
	p, err := h.currentPrincipal(c)
	if err != nil {
		return scope, err
	}
	capability, ok := auditCapability(c.Request().Method, c.Path())
	if !ok || !p.Can(capability, scope) {
		return scope, auditFailure(access.ErrDenied)
	}
	if h.Audit == nil {
		return scope, echo.NewHTTPError(503, "Audit logging is not initialized")
	}
	return scope, nil
}

func (h *Handler) auditInfo(c echo.Context, scope access.Scope) (*partials.CommonInfo, error) {
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return nil, err
	}
	if scope.TenantID > 0 && info.TenantID != strconv.Itoa(scope.TenantID) || scope.SiteID > 0 && info.SiteID != strconv.Itoa(scope.SiteID) {
		return nil, echo.NewHTTPError(404, "Audit scope not found")
	}
	if scope.SiteID == 0 {
		info.SiteID = "-1"
	}
	return info, nil
}

func auditValues(values url.Values, allowed ...string) error {
	for key, entries := range values {
		found := false
		for _, candidate := range allowed {
			if key == candidate {
				found = true
				break
			}
		}
		if !found || len(entries) != 1 {
			return audit.ErrInvalid
		}
	}
	return nil
}

func auditFilter(values url.Values, scope access.Scope, now time.Time) (audit.Filter, error) {
	f := audit.Filter{Scope: scope, Source: values.Get("source"), Actor: values.Get("actor"), Action: values.Get("action"), Resource: values.Get("target"), Result: values.Get("result"), From: now.UTC().AddDate(0, 0, -30).Truncate(time.Second), Until: now.UTC().Truncate(time.Second)}
	for _, entry := range []struct {
		key    string
		target *time.Time
	}{{"from", &f.From}, {"until", &f.Until}} {
		if raw := values.Get(entry.key); raw != "" {
			parsed, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				parsed, err = time.Parse("2006-01-02T15:04:05.999999999", raw)
			}
			if err != nil {
				parsed, err = time.Parse("2006-01-02T15:04", raw)
			}
			if err != nil {
				return f, audit.ErrInvalid
			}
			*entry.target = parsed.UTC()
		}
	}
	return f, f.Validate()
}

func (h *Handler) AuditLog(c echo.Context) error {
	scope, err := h.auditScope(c)
	if err != nil {
		return err
	}
	if len(c.Request().URL.RawQuery) > 8192 {
		return auditFailure(audit.ErrInvalid)
	}
	values, err := url.ParseQuery(c.Request().URL.RawQuery)
	if err != nil {
		return auditFailure(audit.ErrInvalid)
	}
	if err = auditValues(values, "source", "actor", "action", "target", "result", "from", "until", "before"); err != nil {
		return auditFailure(err)
	}
	f, err := auditFilter(values, scope, time.Now())
	if err != nil {
		return auditFailure(err)
	}
	page, err := h.Audit.List(c.Request().Context(), h.appleActor(c), f, values.Get("before"))
	if err != nil {
		return auditFailure(err)
	}
	info, err := h.auditInfo(c, scope)
	if err != nil {
		return err
	}
	return renderApple(c, audit_views.Log(c, info, f, page))
}

func (h *Handler) AuditExport(c echo.Context) error {
	scope, err := h.auditScope(c)
	if err != nil {
		return err
	}
	values := c.Request().PostForm
	if err = auditValues(values, "csrf", "format", "source", "actor", "action", "target", "result", "from", "until"); err != nil {
		return auditFailure(err)
	}
	f, err := auditFilter(values, scope, time.Now())
	if err != nil {
		return auditFailure(err)
	}
	var data []byte
	format := values.Get("format")
	typeName := "application/json; charset=utf-8"
	switch format {
	case "csv":
		data, err = h.Audit.ExportCSV(c.Request().Context(), h.appleActor(c), f)
		typeName = "text/csv; charset=utf-8"
	case "json":
		data, err = h.Audit.ExportJSON(c.Request().Context(), h.appleActor(c), f)
	default:
		return auditFailure(audit.ErrInvalid)
	}
	if err != nil {
		return auditFailure(err)
	}
	c.Response().Header().Set("Content-Disposition", `attachment; filename="openuem-audit-`+time.Now().UTC().Format("20060102T150405Z")+`.`+format+`"`)
	return c.Blob(http.StatusOK, typeName, data)
}

func (h *Handler) AuditRetention(c echo.Context) error {
	scope, err := h.auditScope(c)
	if err != nil {
		return err
	}
	return h.renderAuditRetention(c, scope, nil)
}

func (h *Handler) renderAuditRetention(c echo.Context, scope access.Scope, preview *audit.RetentionPreview) error {
	policy, history, err := h.Audit.Retention(c.Request().Context(), h.appleActor(c), scope)
	if err != nil {
		return auditFailure(err)
	}
	info, err := h.auditInfo(c, scope)
	if err != nil {
		return err
	}
	return renderApple(c, audit_views.Retention(c, info, scope, policy, history, preview))
}

func (h *Handler) AuditRetentionPreview(c echo.Context) error {
	scope, err := h.auditScope(c)
	if err != nil {
		return err
	}
	values := c.Request().PostForm
	if err = auditValues(values, "csrf", "days"); err != nil {
		return auditFailure(err)
	}
	days, err := strconv.Atoi(values.Get("days"))
	if err != nil {
		return auditFailure(audit.ErrInvalid)
	}
	preview, err := h.Audit.PreviewRetention(c.Request().Context(), h.appleActor(c), scope, days)
	if err != nil {
		return auditFailure(err)
	}
	return h.renderAuditRetention(c, scope, preview)
}

func (h *Handler) AuditRetentionApply(c echo.Context) error {
	scope, err := h.auditScope(c)
	if err != nil {
		return err
	}
	values := c.Request().PostForm
	if err = auditValues(values, "csrf", "preview", "token", "confirm"); err != nil {
		return auditFailure(err)
	}
	if values.Get("confirm") != "yes" {
		return echo.NewHTTPError(400, "Confirm the ongoing retention policy after reviewing the preview")
	}
	if err = h.Audit.ApplyRetention(c.Request().Context(), h.appleActor(c), scope, values.Get("preview"), values.Get("token")); err != nil {
		return auditFailure(err)
	}
	return c.Redirect(http.StatusSeeOther, audit_views.BaseURL(scope)+"/retention")
}
