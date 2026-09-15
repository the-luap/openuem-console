package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

func windowsUpdateFormNames() []string {
	names := []string{"name", "request_key", "mode", "hours", "confirm_policy"}
	for _, field := range windows_views.UpdatePolicyFields() {
		names = append(names, field.Name)
	}
	return names
}

func parseWindowsUpdatePolicy(form url.Values) (windows.UpdatePolicy, time.Duration, error) {
	var policy windows.UpdatePolicy
	name := form.Get("name")
	if name == "" || len(name) > 128 || !utf8.ValidString(name) || strings.TrimSpace(name) != name || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return policy, 0, fmt.Errorf("Use a short policy name without surrounding spaces or control characters")
	}
	key, err := uuid.Parse(form.Get("request_key"))
	if err != nil || key == uuid.Nil || key.String() != form.Get("request_key") {
		return policy, 0, fmt.Errorf("The request identifier is invalid. Start a new policy run.")
	}
	if form.Get("mode") != "apply" && form.Get("mode") != "remove" {
		return policy, 0, fmt.Errorf("Choose whether to apply or remove the selected settings")
	}
	hours, err := strconv.Atoi(form.Get("hours"))
	if err != nil || hours < 1 || hours > 168 || strconv.Itoa(hours) != form.Get("hours") {
		return policy, 0, fmt.Errorf("Choose an admission lifetime from 1 to 168 whole hours")
	}
	policy, err = parseWindowsUpdateSettings(form)
	return policy, time.Duration(hours) * time.Hour, err
}

// Runs and reusable rings use the same optional typed settings and dependencies.
func parseWindowsUpdateSettings(form url.Values) (windows.UpdatePolicy, error) {
	var policy windows.UpdatePolicy
	values := map[string]any{}
	for _, field := range windows_views.UpdatePolicyFields() {
		value := form.Get(field.Name)
		if value == "" {
			continue
		}
		if field.Boolean {
			if value != "true" && value != "false" {
				return policy, fmt.Errorf("Choose Unmanaged, Yes or No for %s", field.Label)
			}
			values[field.Name] = value == "true"
			continue
		}
		number, err := strconv.Atoi(value)
		if err != nil || strconv.Itoa(number) != value || number < field.Minimum || number > field.Maximum {
			return policy, fmt.Errorf("%s must be a whole number from %d to %d, or blank for Unmanaged", field.Label, field.Minimum, field.Maximum)
		}
		values[field.Name] = number
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return policy, windows.ErrUpdatePolicy
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&policy) != nil || policy.Validate() != nil {
		return policy, fmt.Errorf("Select at least one setting. Grace and reboot choices need their matching deadline. Set both active-hours endpoints with a nonzero span within the maximum range.")
	}
	return policy, nil
}

func (h *Handler) windowsUpdateFormContext(c echo.Context) (*partials.CommonInfo, access.Scope, *windows.DeviceMetadata, error) {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return nil, scope, nil, err
	}
	if err := h.windowsReady(); err != nil {
		return nil, scope, nil, err
	}
	device, err := h.Windows.Device(c.Request().Context(), h.appleActor(c), scope, c.Param("id"))
	if err != nil {
		return nil, scope, nil, windowsFailure(err)
	}
	if device.RevokedAt != nil || device.CertificateRevokedAt != nil || !device.CertificateExpiresAt.After(time.Now()) {
		return nil, scope, nil, windowsFailure(windows.ErrManagementIdentity)
	}
	return info, scope, device, nil
}

func (h *Handler) WindowsNewUpdatePolicy(c echo.Context) error {
	info, _, device, err := h.windowsUpdateFormContext(c)
	if err != nil {
		return err
	}
	form := url.Values{"name": {"Windows update policy"}, "mode": {"apply"}, "hours": {"24"}, "request_key": {uuid.NewString()}}
	return renderApple(c, windows_views.UpdatePolicyForm(c, info, *device, windows_views.UpdatePolicyDraft{Form: form}))
}

func (h *Handler) WindowsPreviewUpdatePolicy(c echo.Context) error {
	info, _, device, err := h.windowsUpdateFormContext(c)
	if err != nil {
		return err
	}
	form, err := windowsForm(c, append(windowsUpdateFormNames(), "edit_policy")...)
	if err != nil {
		return err
	}
	policy, _, err := parseWindowsUpdatePolicy(form)
	if err != nil {
		c.Response().Status = 400
		return renderApple(c, windows_views.UpdatePolicyForm(c, info, *device, windows_views.UpdatePolicyDraft{Form: form, Error: err.Error()}))
	}
	if form.Get("edit_policy") == "yes" {
		return renderApple(c, windows_views.UpdatePolicyForm(c, info, *device, windows_views.UpdatePolicyDraft{Form: form}))
	}
	if form.Get("edit_policy") != "" {
		return echo.NewHTTPError(400, "Invalid policy review action")
	}
	return renderApple(c, windows_views.UpdatePolicyPreview(c, info, *device, windows_views.UpdatePolicyDraft{Form: form, Policy: policy}))
}

func (h *Handler) WindowsCreateUpdatePolicy(c echo.Context) error {
	info, scope, device, err := h.windowsUpdateFormContext(c)
	if err != nil {
		return err
	}
	form, err := windowsForm(c, windowsUpdateFormNames()...)
	if err != nil {
		return err
	}
	policy, lifetime, err := parseWindowsUpdatePolicy(form)
	if err != nil {
		return echo.NewHTTPError(400, err.Error())
	}
	if form.Get("confirm_policy") != "yes" {
		return echo.NewHTTPError(400, "Review and confirm the policy and its device before queuing it")
	}
	run, err := h.Windows.EnqueueUpdatePolicy(c.Request().Context(), h.appleActor(c), scope, device.ID, form.Get("request_key"), form.Get("name"), policy, form.Get("mode") == "remove", lifetime)
	if err != nil {
		return windowsFailure(err)
	}
	return appleRedirect(c, info, "/windows/"+device.ID+"/updates/"+run.ID)
}
