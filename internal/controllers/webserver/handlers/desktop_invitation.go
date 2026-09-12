package handlers

import (
	"context"
	"errors"
	"mime"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/desktop"
	"github.com/open-uem/openuem-console/internal/views/desktop_views"
)

// DesktopCreateInvitation takes scope only from the authorized navigation and
// origin only from server configuration. The submitted digest binds the form to
// the release the operator reviewed; catalog admission rechecks it transactionally.
func (h *Handler) DesktopCreateInvitation(c echo.Context) error {
	info, scope, err := h.desktopInfo(c)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), 30*time.Second)
	defer cancel()
	c.SetRequest(c.Request().WithContext(ctx))
	data, err := h.desktopEnrollmentData(c, info, scope)
	if err != nil {
		return err
	}
	fail := func(status int, message string) error {
		data.FormError = message
		c.Response().Status = status
		return renderApple(c, desktop_views.Enrollment(c, info, data))
	}
	if scope.SiteID <= 0 {
		return fail(400, "Select a specific site before creating an invitation.")
	}
	if h.Desktop == nil || h.DesktopCatalog == nil || !h.DesktopBootstrapReady || data.Authority == nil || data.InvitationSetup != "" {
		return fail(503, "Complete organization identity and approved agent release setup before creating an invitation.")
	}
	media, _, mediaErr := mime.ParseMediaType(c.Request().Header.Get("Content-Type"))
	if mediaErr != nil || media != "application/x-www-form-urlencoded" || c.Request().URL.RawQuery != "" || c.Request().ContentLength > 8192 || c.Request().ParseForm() != nil {
		return fail(400, "Submit a valid enrollment invitation form.")
	}
	form := c.Request().PostForm
	allowed := map[string]bool{"csrf": true, "target": true, "release_digest": true, "max_uses": true, "hours": true, "confirm_create": true}
	if len(form) != len(allowed) || len(form.Encode()) > 8192 {
		return fail(400, "Submit a complete enrollment invitation form.")
	}
	for key, values := range form {
		if !allowed[key] || len(values) != 1 {
			return fail(400, "Submit each invitation setting exactly once.")
		}
	}
	uses, usesErr := strconv.Atoi(form.Get("max_uses"))
	hours, hoursErr := strconv.Atoi(form.Get("hours"))
	if usesErr != nil || uses < 1 || uses > 1000 || hoursErr != nil || (hours != 1 && hours != 4 && hours != 24 && hours != 72 && hours != 168) || form.Get("confirm_create") != "yes" {
		return fail(400, "Choose 1–1000 computers, a listed validity period, and confirm the selected organization and site.")
	}
	data.InvitationForm = desktop_views.InvitationForm{Target: form.Get("target"), MaxUses: uses, Hours: hours}
	platform, architecture, ok := strings.Cut(form.Get("target"), "/")
	matched := false
	for _, target := range data.Targets {
		matched = matched || (target.Platform == platform && target.Architecture == architecture)
	}
	if !ok || !matched {
		return fail(400, "Choose a computer type available in the approved release.")
	}
	if form.Get("release_digest") != data.ReleaseDigest {
		return fail(409, "The approved agent release changed. Review the current release and submit the invitation again.")
	}
	expires := time.Now().UTC().Add(time.Duration(hours) * time.Hour)
	if expires.After(data.ReleaseExpires) {
		expires = data.ReleaseExpires
	}
	invitation, err := h.Desktop.InviteInstaller(ctx, h.DesktopCatalog, registry.InvitationOptions{Scope: scope, Platform: platform, Architecture: architecture, MaxUses: uses, ExpiresAt: expires}, data.ReleaseDigest, h.PublicOrigin, h.appleActor(c))
	if err != nil {
		if errors.Is(err, desktop.ErrNoRelease) || errors.Is(err, desktop.ErrWithdrawn) {
			return fail(409, "The approved agent release changed or was withdrawn. Reload this page before creating an invitation.")
		}
		if errors.Is(err, registry.ErrNotFound) {
			return fail(409, "The selected site or organization identity changed. Reload this page before creating an invitation.")
		}
		return fail(503, "The invitation could not be created. Check the approved package and organization setup, then try again.")
	}
	// The sole token-bearing response is produced only after the audited commit.
	// No token is saved in a session, query string, redirect or invitation listing.
	data.Created = invitation
	return renderApple(c, desktop_views.Enrollment(c, info, data))
}
