package handlers

import (
	"errors"
	"strconv"
	"strings"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	model "github.com/open-uem/openuem-console/internal/models/servers"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views"
	"github.com/open-uem/openuem-console/internal/views/filters"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func (h *Handler) GetCommonInfo(c echo.Context) (*partials.CommonInfo, error) {
	var err error
	var tenant *ent.Tenant
	principal, err := h.currentPrincipal(c)
	if err != nil {
		return nil, err
	}

	csrfToken, ok := c.Get("csrf").(string)
	if c.Request().Method != "GET" && (!ok || csrfToken == "") {
		return nil, errors.New("could not find CSRF token")
	}

	info := partials.CommonInfo{
		EndpointInboundDisabled: h.IndividualAgentService != nil,
		Principal:               principal,
		SM:                      h.SessionManager,
		CurrentVersion:          h.Version,
		Translator:              views.GetTranslatorForDates(c),
		IsAdmin:                 strings.Contains(c.Path(), "/admin"),
		IsProfile:               strings.Contains(c.Path(), "/profiles"),
		IsTask:                  strings.Contains(c.Path(), "/tasks"),
		CSRFToken:               csrfToken,
	}

	if strings.Contains(c.Request().URL.String(), "computers") && !strings.HasSuffix(c.Request().URL.String(), "computers") {
		info.IsComputer = true
	}

	// check if we're running in Docker or no server updater info is stored
	allUpdateServers, err := h.Model.GetAllUpdateServers(filters.UpdateServersFilter{})
	if err != nil {
		return nil, err
	}
	info.IsDocker = len(allUpdateServers) == 0

	latestRelease, err := model.GetLatestServerReleaseFromAPI(h.ServerReleasesFolder)
	if err != nil {
		return nil, err
	}

	info.LatestVersion = latestRelease.Version

	tenantID := c.Param("tenant")
	siteID := c.Param("site")

	info.Tenants, err = h.Model.GetTenants()
	if err != nil {
		return nil, err
	}

	visibleTenants := info.Tenants[:0]
	for _, candidate := range info.Tenants {
		if principal.HasOrganization(candidate.ID) {
			visibleTenants = append(visibleTenants, candidate)
		}
	}
	info.Tenants = visibleTenants
	if (tenantID == "" && principal.IsAdministrator() && (info.IsAdmin || info.IsProfile || info.IsTask)) || strings.HasPrefix(c.Path(), "/myaccount") {
		info.TenantID = "-1"
		info.SiteID = "-1"
		return &info, nil
	}
	if len(info.Tenants) == 0 {
		return nil, echo.NewHTTPError(403, "No organization access is assigned to this account")
	}
	if tenantID == "" {
		preferred, err := h.Model.GetDefaultTenant()
		if err != nil {
			return nil, err
		}
		tenant = info.Tenants[0]
		for _, candidate := range info.Tenants {
			if candidate.ID == preferred.ID {
				tenant = candidate
				break
			}
		}
		info.TenantID = strconv.Itoa(tenant.ID)
	} else {
		id, err := strconv.Atoi(tenantID)
		if err != nil || id <= 0 || strconv.Itoa(id) != tenantID {
			return nil, echo.NewHTTPError(404, "Organization not found")
		}
		for _, candidate := range info.Tenants {
			if candidate.ID == id {
				tenant = candidate
				break
			}
		}
		if tenant == nil {
			return nil, echo.NewHTTPError(404, "Organization not found")
		}
		info.TenantID = tenantID
	}
	info.Sites, err = h.Model.GetAssociatedSites(tenant)
	if err != nil {
		return nil, err
	}
	visibleSites := info.Sites[:0]
	for _, candidate := range info.Sites {
		if principal.Can(access.ReadDevices, access.Scope{TenantID: tenant.ID, SiteID: candidate.ID}) {
			visibleSites = append(visibleSites, candidate)
		}
	}
	info.Sites = visibleSites
	if siteID != "" {
		id, err := strconv.Atoi(siteID)
		if err != nil || id <= 0 || strconv.Itoa(id) != siteID {
			return nil, echo.NewHTTPError(404, "Site not found")
		}
		found := false
		for _, candidate := range info.Sites {
			if candidate.ID == id {
				found = true
				break
			}
		}
		if !found {
			return nil, echo.NewHTTPError(404, "Site not found")
		}
		info.SiteID = siteID
		info.ProfileSiteID = siteID
	} else {
		info.SiteID = "-1"
		info.ProfileSiteID = "-1"
		if len(info.Sites) > 0 {
			info.ProfileSiteID = strconv.Itoa(info.Sites[0].ID)
			if !principal.Can(access.ReadDevices, access.Scope{TenantID: tenant.ID}) {
				info.SiteID = info.ProfileSiteID
			}
		}
	}

	info.DetectRemoteAgents, err = h.Model.GetDefaultDetectRemoteAgents(info.TenantID)
	if err != nil {
		return nil, errors.New(i18n.T(c.Request().Context(), "settings.could_not_get_detect_remote_agents_setting"))
	}

	// is turnstile enabled
	tsSiteKey, tsSecretKey, err := h.Model.GetTurnstileSettings()
	if err != nil {
		return nil, errors.New(i18n.T(c.Request().Context(), "settings.turnstile_could_not_get_settings", err))
	}

	info.IsTurnstileEnabled = tsSecretKey != "" && tsSiteKey != ""

	return &info, nil
}

func (h *Handler) GetAdminTenantName(commonInfo *partials.CommonInfo) string {
	tenantName := ""
	if commonInfo.TenantID != "-1" {
		tenantID, err := strconv.Atoi(commonInfo.TenantID)
		if err != nil {
			return ""
		}

		t, err := h.Model.GetTenantByID(tenantID)
		if err != nil {
			return ""
		}
		tenantName = t.Description
	}
	return tenantName
}

func (h *Handler) GetAdminSiteName(commonInfo *partials.CommonInfo) string {
	siteName := ""
	if commonInfo.TenantID != "-1" {
		tenantID, err := strconv.Atoi(commonInfo.TenantID)
		if err != nil {
			return ""
		}

		siteID, err := strconv.Atoi(commonInfo.SiteID)
		if err != nil {
			return ""
		}

		s, err := h.Model.GetSiteById(tenantID, siteID)
		if err != nil {
			return ""
		}

		siteName = s.Description
	}
	return siteName
}
