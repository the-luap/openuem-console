package handlers

import (
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"net/http"
	"net/url"
)

// Legacy nickname forms must open the revision-bound editor before saving.
func (h *Handler) Nickname(c echo.Context) error {
	info, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}
	return c.Redirect(http.StatusSeeOther, partials.GetNavigationUrl(info, "/computers/"+url.PathEscape(c.Param("uuid"))+"/details"))
}
