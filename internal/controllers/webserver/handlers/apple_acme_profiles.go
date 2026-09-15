package handlers

import (
	"errors"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
)

func appleACMESettings(c echo.Context, settings map[string]any) error {
	f, err := adeEnrollmentForm(c, "editor", "name", "identifier", "payload_scope", "directory_url", "client_identifier", "key_type", "key_size", "hardware_bound", "attest", "subject", "san_email", "san_dns", "san_uri", "san_principal", "extended_key_usage", "usage_flags", "key_extractable", "all_apps_access")
	if err != nil {
		return err
	}
	if f.Get("editor") != "apple-acme" || f.Get("payload_scope") != "System" && f.Get("payload_scope") != "User" {
		return echo.NewHTTPError(400, "Select the ACME editor and System or User scope")
	}
	for key, field := range map[string]string{"DirectoryURL": "directory_url", "ClientIdentifier": "client_identifier", "KeyType": "key_type", "SubjectLines": "subject"} {
		settings[key] = f.Get(field)
	}
	for key, field := range map[string]string{"rfc822Name": "san_email", "dNSName": "san_dns", "uniformResourceIdentifier": "san_uri", "ntPrincipalName": "san_principal", "ExtendedKeyUsageLines": "extended_key_usage"} {
		if value := f.Get(field); value != "" {
			settings[key] = value
		}
	}
	for key, field := range map[string]string{"KeySize": "key_size", "UsageFlags": "usage_flags"} {
		value := f.Get(field)
		if value == "" && key == "UsageFlags" {
			continue
		}
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || strconv.Itoa(n) != value {
			return echo.NewHTTPError(400, "Select valid ACME key size and usage options")
		}
		settings[key] = n
	}
	for key, field := range map[string]string{"HardwareBound": "hardware_bound", "Attest": "attest", "KeyIsExtractable": "key_extractable", "AllowAllAppsAccess": "all_apps_access"} {
		switch f.Get(field) {
		case "":
			if key == "HardwareBound" {
				return echo.NewHTTPError(400, "Select whether the ACME key is hardware-bound")
			}
		case "true", "false":
			settings[key] = f.Get(field) == "true"
		default:
			return echo.NewHTTPError(400, "Select valid ACME hardware, attestation and key access options")
		}
	}
	return nil
}

func acmeHistoryFailure(err error) error {
	switch {
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(403, "Organization profile management and assignment permissions are required")
	case errors.Is(err, apple.ErrNotFound):
		return echo.NewHTTPError(404, "Historical profile not found in this organization")
	case errors.Is(err, apple.ErrConflict):
		return echo.NewHTTPError(409, "This historical profile changed or was already reviewed. Reload its history.")
	case errors.Is(err, apple.ErrACMEHistory):
		return echo.NewHTTPError(400, "Select the original profile archive for this revision and describe its source in 1–1000 characters")
	default:
		return echo.NewHTTPError(503, "The historical profile review could not complete. Check server availability before retrying.")
	}
}

func (h *Handler) AppleACMEHistory(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	state := c.QueryParam("state")
	if state == "" {
		state = "unresolved"
	}
	items, next, err := h.Apple.ACMELegacyProfiles(c.Request().Context(), scope.TenantID, c.QueryParam("after"), state)
	if err != nil {
		return acmeHistoryFailure(err)
	}
	if err = h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "acme.history.read", state); err != nil {
		return acmeHistoryFailure(err)
	}
	canReview := info.Principal.Can(access.ManageProfiles, access.Scope{TenantID: scope.TenantID}) && info.Principal.Can(access.AssignProfiles, access.Scope{TenantID: scope.TenantID})
	return RenderView(c, mdm_views.ACMEHistory(c, info, items, next, state, canReview))
}

func (h *Handler) AppleReviewACMEHistory(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := profileRevisionParameter(c.Param("legacy"))
	if err != nil {
		return err
	}
	if c.Request().URL.RawQuery != "" || c.Request().URL.ForceQuery || c.Request().ParseMultipartForm(apple.MaxProfileBytes+8192) != nil {
		return acmeHistoryFailure(apple.ErrACMEHistory)
	}
	form := c.Request().MultipartForm
	if form == nil {
		return acmeHistoryFailure(apple.ErrACMEHistory)
	}
	defer form.RemoveAll()
	f := c.Request().PostForm
	allowed := map[string]bool{"csrf": true, "confirmed": true, "expected_revision": true, "reason": true}
	for key, values := range f {
		if !allowed[key] || len(values) != 1 {
			return acmeHistoryFailure(apple.ErrACMEHistory)
		}
	}
	if len(f["csrf"]) != 1 || f.Get("confirmed") != "yes" || len(form.File) != 1 || len(form.File["profile"]) != 1 {
		return acmeHistoryFailure(apple.ErrACMEHistory)
	}
	expected, err := strconv.Atoi(f.Get("expected_revision"))
	if err != nil || expected <= 0 || strconv.Itoa(expected) != f.Get("expected_revision") {
		return acmeHistoryFailure(apple.ErrACMEHistory)
	}
	data, err := readAppleUpload(c, "profile", apple.MaxProfileBytes)
	if err != nil {
		return acmeHistoryFailure(apple.ErrACMEHistory)
	}
	if err = h.Apple.ReviewACMELegacyProfile(c.Request().Context(), scope.TenantID, id, expected, data, f.Get("reason"), h.appleActor(c), h.Access); err != nil {
		return acmeHistoryFailure(err)
	}
	return appleRedirect(c, info, "/ios/configurations/acme-history?state=reviewed")
}
