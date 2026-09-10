package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
)

func (h *Handler) WindowsExportCSPCommand(c echo.Context) error {
	_, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	form, err := windowsForm(c, "expected_revision")
	if err != nil {
		return err
	}
	revision, err := parseWindowsCSPRevision(form.Get("expected_revision"))
	if err != nil {
		return err
	}
	message := 0
	if raw := c.Param("message"); raw != "" {
		message, err = strconv.Atoi(raw)
		if err != nil || message < 1 || message > 64 || strconv.Itoa(message) != raw {
			return echo.NewHTTPError(400, "Invalid observation identifier")
		}
	}
	export, err := h.Windows.ExportCSPCommand(c.Request().Context(), h.appleActor(c), scope, c.Param("id"), c.Param("command"), revision, message)
	if err != nil {
		switch {
		case errors.Is(err, windows.ErrCSPExportTooLarge):
			return echo.NewHTTPError(422, "The evidence exceeds 32 MiB. Download individual observations from the observation history.")
		case errors.Is(err, windows.ErrCSPExportBusy):
			c.Response().Header().Set("Retry-After", "5")
			return echo.NewHTTPError(429, "Another Windows evidence export is being prepared. Try again shortly.")
		case errors.Is(err, windows.ErrCSPConflict):
			return echo.NewHTTPError(409, "The command changed. Refresh its evidence page before downloading.")
		default:
			return windowsCSPFailure(err)
		}
	}
	defer clear(export.Data)
	filename := fmt.Sprintf("windows-csp-%s-r%d", c.Param("command"), revision)
	if message != 0 {
		filename += "-message-" + strconv.Itoa(message)
	}
	digest := sha256.Sum256(export.Data)
	header := c.Response().Header()
	header.Set("Content-Disposition", `attachment; filename="`+filename+`.json"`)
	header.Set("Content-Length", strconv.Itoa(len(export.Data)))
	header.Set("X-Content-SHA256", hex.EncodeToString(digest[:]))
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	return c.Blob(http.StatusOK, "application/json; charset=utf-8", export.Data)
}
