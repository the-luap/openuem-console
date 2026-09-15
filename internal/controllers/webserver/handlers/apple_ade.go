package handlers

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/ade"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
)

func adeHeaders(c echo.Context) {
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Referrer-Policy", "no-referrer")
	c.Response().Header().Set("X-Content-Type-Options", "nosniff")
}
func adeFailure(err error) error {
	var retry *ade.RetryError
	switch {
	case errors.As(err, &retry):
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Apple requested a later retry. Reload the connection page to see its retry deadline. Existing credentials have been retained.")
	case errors.Is(err, access.ErrDenied):
		return echo.NewHTTPError(http.StatusForbidden, "Automated Device Enrollment permission denied")
	case errors.Is(err, apple.ErrNotFound):
		return echo.NewHTTPError(http.StatusNotFound, "Automated Device Enrollment connection not found")
	case errors.Is(err, apple.ErrADEAccount):
		return echo.NewHTTPError(http.StatusConflict, "This Apple server is already connected elsewhere or the token belongs to a different Apple server or organization. Renew the existing connection using its original Apple server.")
	case errors.Is(err, ade.ErrToken):
		return echo.NewHTTPError(http.StatusBadRequest, "Select a current Apple server token encrypted for this connection's certificate. Renewals must not expire earlier than the previous token.")
	case errors.Is(err, apple.ErrADE):
		return echo.NewHTTPError(http.StatusBadRequest, "Check the connection name, status and selected action. Each organization supports up to 16 retained connections.")
	case errors.Is(err, ade.ErrAuthorization):
		return echo.NewHTTPError(http.StatusBadRequest, "Apple rejected this token. Download a current server token from Apple Business Manager or Apple School Manager.")
	default:
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Apple server verification is temporarily unavailable. Existing credentials and assignments have been retained; try again later.")
	}
}

// Read body fields only. Query fallback and duplicate fields must not change the
// selected operation, confirmation, token or CSRF identity.
func adeForm(c echo.Context, upload bool) (url.Values, error) {
	var err error
	if upload {
		err = c.Request().ParseMultipartForm(ade.MaxTokenFile + 8192)
	} else {
		err = c.Request().ParseForm()
	}
	if err != nil {
		return nil, echo.NewHTTPError(400, "Invalid Automated Device Enrollment form")
	}
	f := c.Request().PostForm
	allowed := map[string]bool{"csrf": true, "name": true, "operation": true, "confirmed": true}
	for k, v := range f {
		if !allowed[k] || len(v) != 1 {
			return nil, echo.NewHTTPError(400, "Ambiguous Automated Device Enrollment form")
		}
	}
	if len(c.QueryParams()) != 0 || len(f["csrf"]) != 1 {
		return nil, echo.NewHTTPError(400, "Invalid Automated Device Enrollment form")
	}
	if upload {
		m := c.Request().MultipartForm
		if m == nil || len(m.File) != 1 || len(m.File["token"]) != 1 {
			return nil, echo.NewHTTPError(400, "Select exactly one Apple server token file")
		}
	}
	return f, nil
}

func (h *Handler) AppleADE(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	selected, after, targetAfter := c.QueryParam("server"), c.QueryParam("after"), c.QueryParam("target_after")
	if len(c.QueryParams()["server"]) > 1 || len(c.QueryParams()["after"]) > 1 || len(c.QueryParams()["target_after"]) > 1 {
		return echo.NewHTTPError(400, "Invalid assignment page")
	}
	if selected != "" {
		if _, err = uuid.Parse(selected); err != nil {
			return echo.NewHTTPError(404, "Connection not found")
		}
	}
	servers, err := h.Apple.ADEServers(c.Request().Context(), scope.TenantID)
	if err != nil {
		return adeFailure(err)
	}
	if selected == "" && len(servers) > 0 {
		selected = servers[0].ID
	}
	found := selected == ""
	for _, s := range servers {
		if s.ID == selected {
			found = true
		}
	}
	if !found {
		return echo.NewHTTPError(404, "Connection not found")
	}
	devices := []apple.ADEDevice{}
	enrollment := mdm_views.ADEEnrollment{}
	next := ""
	if selected != "" {
		devices, next, err = h.Apple.ADEDevices(c.Request().Context(), scope.TenantID, selected, after)
		if err != nil {
			return adeFailure(err)
		}
		enrollment.Profiles, err = h.Apple.ADEProfiles(c.Request().Context(), scope.TenantID, selected)
		if err != nil {
			return adeWorkflowFailure(err)
		}
		enrollment.Targets, enrollment.Next, err = h.Apple.ADETargets(c.Request().Context(), scope.TenantID, selected, targetAfter)
		if err != nil {
			return adeWorkflowFailure(err)
		}
	} else if after != "" || targetAfter != "" {
		return echo.NewHTTPError(400, "Select a connection first")
	}
	if err = h.Apple.RecordRead(c.Request().Context(), apple.Scope{TenantID: scope.TenantID}, h.appleActor(c), "ade.inventory.read", "connections"); err != nil {
		return adeFailure(err)
	}
	return renderApple(c, mdm_views.ADE(c, info, servers, selected, devices, next, enrollment))
}
func (h *Handler) AppleCreateADEServer(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	f, err := adeForm(c, false)
	if err != nil {
		return err
	}
	id, err := h.Apple.CreateADEServer(c.Request().Context(), scope.TenantID, f.Get("name"), h.appleActor(c), h.Access)
	if err != nil {
		return adeFailure(err)
	}
	return appleRedirect(c, info, "/ios/ade?server="+url.QueryEscape(id))
}
func (h *Handler) AppleADECertificate(c echo.Context) error {
	adeHeaders(c)
	_, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	data, err := h.Apple.ADEServerCertificate(c.Request().Context(), scope.TenantID, id, h.appleActor(c), h.Access)
	if err != nil {
		return adeFailure(err)
	}
	c.Response().Header().Set("Content-Disposition", `attachment; filename="openuem-ade-`+id+`.pem"`)
	return c.Blob(http.StatusOK, "application/x-pem-file", data)
}
func (h *Handler) AppleImportADEToken(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	f, err := adeForm(c, true)
	if err != nil {
		return err
	}
	if f.Get("confirmed") != "yes" {
		return echo.NewHTTPError(400, "Confirm that the token is for this organization's Apple server")
	}
	data, err := readAppleUpload(c, "token", ade.MaxTokenFile)
	if err != nil {
		return adeFailure(ade.ErrToken)
	}
	defer clear(data)
	if err = h.Apple.ImportADEToken(c.Request().Context(), scope.TenantID, id, data, h.appleActor(c), h.Access); err != nil {
		return adeFailure(err)
	}
	return appleRedirect(c, info, "/ios/ade?server="+url.QueryEscape(id))
}
func (h *Handler) AppleChangeADEServer(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	f, err := adeForm(c, false)
	if err != nil {
		return err
	}
	op := f.Get("operation")
	if (op == "disable" || op == "reload") && f.Get("confirmed") != "yes" {
		return echo.NewHTTPError(400, "Confirm the connection action")
	}
	if err = h.Apple.ChangeADEServer(c.Request().Context(), scope.TenantID, id, op, h.appleActor(c), h.Access); err != nil {
		return adeFailure(err)
	}
	return appleRedirect(c, info, "/ios/ade?server="+url.QueryEscape(id))
}
