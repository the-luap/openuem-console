package handlers

import (
	"errors"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
)

func profileRevisionFailure(err error) error {
	switch {
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(403, "Organization profile management and assignment permissions are required")
	case errors.Is(err, apple.ErrNotFound):
		return echo.NewHTTPError(404, "Profile revision not found in this organization")
	case errors.Is(err, apple.ErrConflict):
		return echo.NewHTTPError(409, "The current profile changed or this revision is already current. Reload its history before restoring.")
	case errors.Is(err, apple.ErrProfileRevision):
		return echo.NewHTTPError(400, "Select an earlier profile revision and describe the restoration in 1–1000 characters")
	default:
		return echo.NewHTTPError(503, "The profile revision operation could not complete. Check the current assignments and server availability before retrying.")
	}
}

func profileRevisionParameter(value string) (string, error) {
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil || id.String() != value {
		return "", echo.NewHTTPError(400, "Invalid profile or revision identifier")
	}
	return value, nil
}

func (h *Handler) AppleProfileRevisionHistory(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	profile := c.Param("id")
	if profile != "" {
		if profile, err = profileRevisionParameter(profile); err != nil {
			return err
		}
	}
	items, next, err := h.Apple.ProfileRevisions(c.Request().Context(), scope.TenantID, profile, c.QueryParam("before"))
	if err != nil {
		return profileRevisionFailure(err)
	}
	resource := profile
	if resource == "" {
		resource = "catalog"
	}
	if err = h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "profile.history.read", resource); err != nil {
		return profileRevisionFailure(err)
	}
	canRestore := info.Principal.Can(access.ManageProfiles, access.Scope{TenantID: scope.TenantID}) && info.Principal.Can(access.AssignProfiles, access.Scope{TenantID: scope.TenantID})
	return RenderView(c, mdm_views.ProfileRevisionHistory(c, info, profile, items, next, canRestore))
}

func (h *Handler) AppleDownloadProfileRevision(c echo.Context) error {
	adeHeaders(c)
	_, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	profile, err := profileRevisionParameter(c.Param("id"))
	if err != nil {
		return err
	}
	revision, err := profileRevisionParameter(c.Param("revision"))
	if err != nil {
		return err
	}
	p, err := h.Apple.ProfileRevisionPayload(c.Request().Context(), scope.TenantID, revision)
	if err != nil {
		return profileRevisionFailure(err)
	}
	if p.ID != profile {
		return profileRevisionFailure(apple.ErrNotFound)
	}
	if err = h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "profile.revision.download", revision); err != nil {
		return profileRevisionFailure(err)
	}
	c.Response().Header().Set("Content-Disposition", `attachment; filename="profile-revision.mobileconfig"`)
	return c.Blob(200, "application/x-apple-aspen-config", p.Payload)
}

func (h *Handler) AppleRestoreProfileRevision(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	profile, err := profileRevisionParameter(c.Param("id"))
	if err != nil {
		return err
	}
	revision, err := profileRevisionParameter(c.Param("revision"))
	if err != nil {
		return err
	}
	f, err := adeEnrollmentForm(c, "expected_revision", "reason")
	if err != nil {
		return err
	}
	expected, err := strconv.Atoi(f.Get("expected_revision"))
	if err != nil || strconv.Itoa(expected) != f.Get("expected_revision") {
		return profileRevisionFailure(apple.ErrProfileRevision)
	}
	if _, err = h.Apple.RestoreProfileRevision(c.Request().Context(), scope.TenantID, profile, revision, expected, f.Get("reason"), h.appleActor(c), h.Access); err != nil {
		return profileRevisionFailure(err)
	}
	return appleRedirect(c, info, "/ios/configurations/"+profile+"/history")
}
