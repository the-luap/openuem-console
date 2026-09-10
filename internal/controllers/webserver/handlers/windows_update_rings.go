package handlers

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

func windowsRingFormNames() []string {
	names := []string{"ring_id", "request_key", "expected_revision", "name", "enabled", "confirm_ring"}
	for _, field := range windows_views.UpdatePolicyFields() {
		names = append(names, field.Name)
	}
	return names
}

func parseWindowsUpdateRing(form url.Values) (windows.UpdateRingRevision, error) {
	r := windows.UpdateRingRevision{RingID: form.Get("ring_id"), RequestKey: form.Get("request_key"), Name: form.Get("name")}
	for _, raw := range []string{r.RingID, r.RequestKey} {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil || id.String() != raw {
			return r, fmt.Errorf("The ring or request identifier is invalid. Reopen the ring editor.")
		}
	}
	expected, err := strconv.ParseInt(form.Get("expected_revision"), 10, 64)
	if err != nil || expected < 0 || expected >= 1000000 || strconv.FormatInt(expected, 10) != form.Get("expected_revision") {
		return r, fmt.Errorf("The reviewed revision is invalid. Reopen the ring editor.")
	}
	r.Revision = expected + 1
	if r.Name == "" || len(r.Name) > 128 || !utf8.ValidString(r.Name) || strings.TrimSpace(r.Name) != r.Name || strings.IndexFunc(r.Name, unicode.IsControl) >= 0 {
		return r, fmt.Errorf("Use a short ring name without surrounding spaces or control characters")
	}
	if form.Get("enabled") != "true" && form.Get("enabled") != "false" {
		return r, fmt.Errorf("Choose whether this ring is enabled or disabled")
	}
	r.Enabled = form.Get("enabled") == "true"
	r.Policy, err = parseWindowsUpdateSettings(form)
	return r, err
}

func (h *Handler) windowsRingContext(c echo.Context) (*partials.CommonInfo, access.Scope, error) {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return nil, scope, err
	}
	return info, scope, h.windowsReady()
}

func (h *Handler) WindowsUpdateRings(c echo.Context) error {
	info, scope, err := h.windowsRingContext(c)
	if err != nil {
		return err
	}
	offset, err := windowsOffset(c, "offset")
	if err != nil {
		return err
	}
	rings, err := h.Windows.UpdateRings(c.Request().Context(), h.appleActor(c), scope, offset, 26)
	if err != nil {
		return windowsFailure(err)
	}
	more := len(rings) > 25
	if more {
		rings = rings[:25]
	}
	return renderApple(c, windows_views.UpdateRings(c, info, rings, offset, more))
}

func (h *Handler) WindowsUpdateRingHistory(c echo.Context) error {
	info, scope, err := h.windowsRingContext(c)
	if err != nil {
		return err
	}
	var before int64
	if raw, ok := c.QueryParams()["before"]; ok {
		if len(raw) != 1 {
			return echo.NewHTTPError(400, "Invalid ring history page")
		}
		before, err = strconv.ParseInt(raw[0], 10, 64)
		if err != nil || before < 0 || before > 1000001 || strconv.FormatInt(before, 10) != raw[0] {
			return echo.NewHTTPError(400, "Invalid ring history page")
		}
	}
	rings, err := h.Windows.UpdateRingRevisions(c.Request().Context(), h.appleActor(c), scope, c.Param("ring"), before, 26)
	if err != nil {
		return windowsFailure(err)
	}
	more := len(rings) > 25
	if more {
		rings = rings[:25]
	}
	return renderApple(c, windows_views.UpdateRingHistory(c, info, c.Param("ring"), rings, before, more))
}

func (h *Handler) WindowsEditUpdateRing(c echo.Context) error {
	info, scope, err := h.windowsRingContext(c)
	if err != nil {
		return err
	}
	form := url.Values{"ring_id": {uuid.NewString()}, "request_key": {uuid.NewString()}, "expected_revision": {"0"}, "name": {"Windows update ring"}, "enabled": {"true"}}
	if id := c.Param("ring"); id != "" {
		rings, err := h.Windows.UpdateRingRevisions(c.Request().Context(), h.appleActor(c), scope, id, 0, 1)
		if err != nil {
			return windowsFailure(err)
		}
		if len(rings) != 1 {
			return windowsFailure(windows.ErrNotFound)
		}
		if rings[0].Revision >= 1000000 {
			return echo.NewHTTPError(409, "This ring has reached its revision limit. Create a new ring.")
		}
		form = windows_views.UpdateRingFormValues(rings[0], form.Get("request_key"))
	}
	return renderApple(c, windows_views.UpdateRingForm(c, info, windows_views.UpdateRingDraft{Form: form}))
}

func (h *Handler) WindowsPreviewUpdateRing(c echo.Context) error {
	info, scope, err := h.windowsRingContext(c)
	if err != nil {
		return err
	}
	form, err := windowsForm(c, append(windowsRingFormNames(), "edit_ring")...)
	if err != nil {
		return err
	}
	ring, err := parseWindowsUpdateRing(form)
	if err != nil {
		c.Response().Status = 400
		return renderApple(c, windows_views.UpdateRingForm(c, info, windows_views.UpdateRingDraft{Form: form, Error: err.Error()}))
	}
	if ring.Revision > 1 {
		current, err := h.Windows.UpdateRingRevisions(c.Request().Context(), h.appleActor(c), scope, ring.RingID, 0, 1)
		if err != nil {
			return windowsFailure(err)
		}
		if len(current) != 1 || current[0].Revision != ring.Revision-1 {
			c.Response().Status = 409
			return renderApple(c, windows_views.UpdateRingForm(c, info, windows_views.UpdateRingDraft{Form: form, Error: "The ring changed after you opened the editor. Your draft is shown below. Open the latest revision and review your changes again."}))
		}
	}
	if form.Get("edit_ring") == "yes" {
		return renderApple(c, windows_views.UpdateRingForm(c, info, windows_views.UpdateRingDraft{Form: form}))
	}
	if form.Get("edit_ring") != "" {
		return echo.NewHTTPError(400, "Invalid ring review action")
	}
	return renderApple(c, windows_views.UpdateRingPreview(c, info, windows_views.UpdateRingDraft{Form: form, Ring: ring}))
}

func (h *Handler) WindowsSaveUpdateRing(c echo.Context) error {
	info, scope, err := h.windowsRingContext(c)
	if err != nil {
		return err
	}
	form, err := windowsForm(c, windowsRingFormNames()...)
	if err != nil {
		return err
	}
	ring, err := parseWindowsUpdateRing(form)
	if err != nil {
		return echo.NewHTTPError(400, err.Error())
	}
	if form.Get("confirm_ring") != "yes" {
		return echo.NewHTTPError(400, "Review and confirm the ring revision before saving")
	}
	saved, err := h.Windows.SaveUpdateRing(c.Request().Context(), h.appleActor(c), scope, ring.RingID, ring.RequestKey, ring.Revision-1, ring.Name, ring.Policy, ring.Enabled)
	if err != nil {
		if errors.Is(err, windows.ErrUpdateRingConflict) {
			c.Response().Status = 409
			return renderApple(c, windows_views.UpdateRingForm(c, info, windows_views.UpdateRingDraft{Form: form, Error: "The ring or request changed. Your draft has not been saved. Open the latest revision and review your changes again."}))
		}
		return windowsFailure(err)
	}
	return appleRedirect(c, info, "/windows/update-rings/"+saved.RingID)
}
