package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func appleUpdateExceptionFailure(c echo.Context, err error) error {
	status, key := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, access.ErrDenied):
		status, key = http.StatusForbidden, "permission"
	case errors.Is(err, apple.ErrNotFound):
		status, key = http.StatusNotFound, "missing"
	case errors.Is(err, apple.ErrConflict), errors.Is(err, apple.ErrUpdateExceptionReview), errors.Is(err, apple.ErrUpdateExceptionActive):
		status, key = http.StatusConflict, "changed"
	case errors.Is(err, apple.ErrUpdateException):
		status, key = http.StatusBadRequest, "invalid"
	}
	return echo.NewHTTPError(status, i18n.T(c.Request().Context(), "apple_update_exceptions."+key))
}

func (h *Handler) appleUpdateExceptionContext(c echo.Context) (*partials.CommonInfo, apple.Scope, error) {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return nil, scope, err
	}
	if scope.SiteID <= 0 || c.Param("site") == "" {
		return nil, scope, echo.NewHTTPError(http.StatusBadRequest, i18n.T(c.Request().Context(), "apple_update_exceptions.site"))
	}
	if err = h.appleReady(); err != nil {
		return nil, scope, err
	}
	return info, scope, nil
}

func (h *Handler) AppleReviewUpdateException(c echo.Context) error {
	info, scope, err := h.appleUpdateExceptionContext(c)
	if err != nil {
		return err
	}
	if _, err = groupQuery(c); err != nil {
		return appleUpdateExceptionFailure(c, apple.ErrUpdateException)
	}
	p, err := h.Apple.ReviewUpdateException(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("id"))
	if err != nil {
		return appleUpdateExceptionFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdateExceptionReview(c, info, *p, uuid.NewString(), uuid.NewString()))
}

func appleUpdateExceptionForm(c echo.Context) (apple.UpdateExceptionRequest, error) {
	r := apple.UpdateExceptionRequest{DeviceID: c.Param("id")}
	f, err := boundedDeviceManagementForm(c, "apple_update_exceptions.invalid", []string{"csrf", "request_key", "kind", "reason", "expires_at", "review_token", "confirmed"}, 8<<10)
	if err != nil {
		return r, err
	}
	if f.Get("confirmed") != "yes" {
		return r, appleUpdateExceptionFailure(c, apple.ErrUpdateException)
	}
	r.RequestKey, r.Kind, r.ReviewToken = f.Get("request_key"), f.Get("kind"), f.Get("review_token")
	r.Reason = strings.TrimSpace(strings.ReplaceAll(f.Get("reason"), "\r\n", "\n"))
	switch r.Kind {
	case "pause":
		raw := f.Get("expires_at")
		expires, err := time.Parse("2006-01-02T15:04", raw)
		if err != nil || len(raw) != 16 || expires.Format("2006-01-02T15:04") != raw {
			return r, appleUpdateExceptionFailure(c, apple.ErrUpdateException)
		}
		r.ExpiresAt = &expires
	case "resume":
		if _, present := f["expires_at"]; present {
			return r, appleUpdateExceptionFailure(c, apple.ErrUpdateException)
		}
	default:
		return r, appleUpdateExceptionFailure(c, apple.ErrUpdateException)
	}
	return r, nil
}

func (h *Handler) AppleRecordUpdateException(c echo.Context) error {
	info, scope, err := h.appleUpdateExceptionContext(c)
	if err != nil {
		return err
	}
	request, err := appleUpdateExceptionForm(c)
	if err != nil {
		return err
	}
	r, err := h.Apple.RecordUpdateException(c.Request().Context(), h.appleActor(c), h.Access, scope, request)
	if err != nil {
		return appleUpdateExceptionFailure(c, err)
	}
	return appleRedirect(c, info, mdm_views.UpdateExceptionPath(r.DeviceID)+"/"+r.ID)
}

func (h *Handler) AppleUpdateException(c echo.Context) error {
	info, scope, err := h.appleUpdateExceptionContext(c)
	if err != nil {
		return err
	}
	if _, err = groupQuery(c); err != nil {
		return appleUpdateExceptionFailure(c, apple.ErrUpdateException)
	}
	r, err := h.Apple.UpdateExceptionDetails(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("id"), c.Param("exception"))
	if err != nil {
		return appleUpdateExceptionFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdateException(c, info, *r))
}

func (h *Handler) AppleUpdateExceptions(c echo.Context) error {
	info, scope, err := h.appleUpdateExceptionContext(c)
	if err != nil {
		return err
	}
	q, err := groupQuery(c, "before")
	if err != nil {
		return appleUpdateExceptionFailure(c, apple.ErrUpdateException)
	}
	items, next, err := h.Apple.UpdateExceptions(c.Request().Context(), h.appleActor(c), h.Access, scope, c.Param("id"), q.Get("before"))
	if err != nil {
		return appleUpdateExceptionFailure(c, err)
	}
	return renderApple(c, mdm_views.AppleUpdateExceptions(c, info, c.Param("id"), items, next))
}
