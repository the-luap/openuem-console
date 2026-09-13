package handlers

import (
	"fmt"
	"log"
	"net/url"
	"strconv"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/filters"
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

func (h *Handler) EditProfile(c echo.Context, method string, id string, successMessage string) error {
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

	if id == "" {
		id = c.Param("uuid")
		if id == "" {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "profiles.edit.empty_id"), true))
		}
	}

	profileId, err := strconv.Atoi(id)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "profiles.edit.invalid_task"), true))
	}

	profile, err := h.Model.GetProfileById(profileId, commonInfo)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "profiles.edit.retrieve_err"), true))
	}

	p.NItems, err = h.Model.CountAllTasksForProfile(profileId)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "profiles.edit.retrieve_tasks_err"), true))
	}

	tasks, err := h.Model.GetTasksForProfileByPage(p, profileId)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "profiles.edit.retrieve_tasks_err"), true))
	}

	tags, err := h.Model.GetAllTags(commonInfo, filters.AgentFilter{})
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "profiles.edit.no_tags"), true))
	}

	if method == "" {
		method = c.Request().Method
	}

	if successMessage != "" {
		u, err := url.Parse(partials.GetNavigationUrl(commonInfo, fmt.Sprintf("/profiles/%s", id)))
		if err != nil {
			return RenderError(c, partials.ErrorMessage(err.Error(), true))
		}
		return RenderViewWithReplaceUrl(c, profiles_views.ProfilesIndex("| Profiles", profiles_views.EditProfile(c, p, profile, tasks, tags, successMessage, itemsPerPage, commonInfo), commonInfo), u)
	}

	return RenderView(c, profiles_views.ProfilesIndex("| Profiles", profiles_views.EditProfile(c, p, profile, tasks, tags, successMessage, itemsPerPage, commonInfo), commonInfo))
}

func (h *Handler) ProfileIssues(c echo.Context) error {
	var err error

	commonInfo, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}

	profileID := c.Param("uuid")
	if profileID == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "profiles.issues.empty_id"), true))
	}

	itemsPerPage, err := h.Model.GetDefaultItemsPerPage()
	if err != nil {
		log.Println("[ERROR]: could not get items per page from database")
		itemsPerPage = 5
	}

	p := partials.NewPaginationAndSort(itemsPerPage)
	p.GetPaginationAndSortParams(c.FormValue("page"), c.FormValue("pageSize"), c.FormValue("sortBy"), c.FormValue("sortOrder"), c.FormValue("currentSortBy"), itemsPerPage)

	pID, err := strconv.Atoi(profileID)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(err.Error(), true))
	}

	p.NItems, err = h.Model.CountAllProfileIssues(pID)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(err.Error(), false))
	}

	profile, err := h.Model.GetProfileById(pID, commonInfo)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "profiles.edit.retrieve_err"), true))
	}

	issues, err := h.Model.GetProfileIssuesByPage(p, pID)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(err.Error(), true))
	}

	return RenderView(c, profiles_views.ProfilesIndex("| Profiles", profiles_views.ProfilesIssues(c, p, issues, profile, itemsPerPage, commonInfo), commonInfo))
}
