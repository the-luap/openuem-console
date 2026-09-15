package handlers

import (
	"log"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/profiles_views"
)

func (h *Handler) Profiles(c echo.Context, successMessage string) error {
	var err error

	commonInfo, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}

	itemsPerPage, err := h.Model.GetDefaultItemsPerPage()
	if err != nil {
		log.Println("[ERROR]: could not get items per page from database")
		itemsPerPage = 5
	}

	p := partials.NewPaginationAndSort(itemsPerPage)
	p.GetPaginationAndSortParams(c.FormValue("page"), c.FormValue("pageSize"), c.FormValue("sortBy"), c.FormValue("sortOrder"), c.FormValue("currentSortBy"), itemsPerPage)

	p.NItems, err = h.Model.CountAllProfiles(commonInfo)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(err.Error(), false))
	}

	profiles, err := h.Model.GetProfilesByPage(p, commonInfo)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(err.Error(), true))
	}

	refreshTime, err := h.Model.GetDefaultRefreshTime()
	if err != nil {
		log.Println("[ERROR]: could not get refresh time from database")
		refreshTime = 5
	}

	return RenderView(c, profiles_views.ProfilesIndex("| Profiles", profiles_views.Profiles(c, p, profiles, refreshTime, successMessage, itemsPerPage, commonInfo), commonInfo))
}

func (h *Handler) NewProfile(c echo.Context) error {
	var err error

	commonInfo, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}

	return RenderView(c, profiles_views.ProfilesIndex("| Profiles", profiles_views.NewProfile(c, commonInfo), commonInfo))
}
