package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/nats"
	"github.com/open-uem/nats/legacysecret"
	"github.com/open-uem/nats/netbirdapi"
	consolesettings "github.com/open-uem/openuem-console/internal/settings"
	"github.com/open-uem/openuem-console/internal/views/computers_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func (h *Handler) Netbird(c echo.Context, successMessage string) error {
	var err error

	commonInfo, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}

	agentID := c.Param("uuid")

	if agentID == "" {
		return RenderView(c, computers_views.InventoryIndex(" | Inventory", partials.Error(c, "an error occurred getting uuid param", "Computer", partials.GetNavigationUrl(commonInfo, "/computers"), commonInfo), commonInfo))
	}

	// Try to get info using NATS refresh
	msg, err := h.RequestBroker("agent.netbird.refresh."+agentID, nil, 10*time.Second)
	if err == nil {
		result := nats.Netbird{}
		if err := json.Unmarshal(msg.Data, &result); err != nil {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_decode_response", err.Error()), true))
		}

		if result.Error == "" {
			if err := h.Model.SaveNetbirdInfo(agentID, result); err != nil {
				return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_save_data", result.Error), true))
			}
		}
	}

	// Get data from database
	agent, err := h.Model.GetAgentNetBirdById(agentID, commonInfo)
	if err != nil || agent.Edges.Netbird == nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.agent_doesnt_support_netbird"), true))
	}

	sites := agent.Edges.Site
	if len(sites) == 0 {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "agents.could_not_get_associated_site"), true))
	}

	if len(sites) > 1 {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "agents.agent_cannot_associated_to_more_than_one_site"), true))
	}

	currentSite := sites[0]

	s, err := h.Model.GetSite(currentSite.ID)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "agents.could_not_get_site_info"), true))
	}

	if s.Edges.Tenant == nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "agents.could_not_get_tenant"), true))
	}

	currentTenant := s.Edges.Tenant

	allTenants, err := h.Model.GetTenants()
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "agents.could_not_get_tenants"), true))
	}

	allSites, err := h.Model.GetSites(currentTenant.ID)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "agents.could_not_get_sites"), true))
	}

	confirmDelete := c.QueryParam("delete") != ""

	p := partials.PaginationAndSort{}

	higherVersion, err := h.Model.GetHigherAgentReleaseInstalled()
	if err != nil {
		return RenderError(c, partials.ErrorMessage(err.Error(), true))
	}

	tenantID, err := strconv.Atoi(commonInfo.TenantID)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "tenants.could_not_convert_to_int", err.Error()), true))
	}

	settings, err := h.Model.GetNetbirdSettings(c.Request().Context(), tenantID)
	if err != nil {
		if ent.IsNotFound(err) {
			settings = &ent.NetbirdSettings{}
		} else {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_get_settings", err.Error()), true))
		}
	}

	if settings.AccessToken == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.token_empty"), true))
	}

	accessToken, err := legacysecret.Open(settings.AccessToken, h.EncryptionMasterKey)
	if err != nil || accessToken == "" {
		return netbirdSettingsFailure(consolesettings.ErrNetbirdSecret)
	}

	ng, err := netbirdapi.Groups(c.Request().Context(), h.netbirdHTTPTransport, settings.ManagementURL, accessToken)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_get_groups", err.Error()), true))
	}

	netbird := settings.AccessToken != ""

	offline := h.IsAgentOffline(c)

	return RenderView(c, computers_views.InventoryIndex(" | Inventory", computers_views.Netbird(c, p, agent, ng, higherVersion, confirmDelete, successMessage, commonInfo, currentTenant, currentSite, allTenants, allSites, netbird, offline), commonInfo))
}

func (h *Handler) NetbirdInstall(c echo.Context) error {
	commonInfo, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}

	agentID := c.Param("uuid")
	if _, err := h.Model.GetAgentById(agentID, commonInfo); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "agents.could_not_get_agent"), false))
	}

	msg, err := h.RequestBroker("agent.netbird.install."+agentID, nil, 10*time.Minute)
	if err != nil {
		if strings.Contains(err.Error(), "no responders") {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.agent_offline"), true))
		}
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.install_request_failed", err.Error()), true))
	}

	result := nats.Netbird{}
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_decode_response", err.Error()), true))
	}

	if result.Error != "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.install_request_failed", result.Error), true))
	}

	if err := h.Model.SaveNetbirdInfo(agentID, result); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_save_data", result.Error), true))
	}

	successMessage := i18n.T(c.Request().Context(), "netbird.install_request_succeeded")

	return h.Netbird(c, successMessage)
}

func (h *Handler) NetbirdRegister(c echo.Context) error {
	commonInfo, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}

	agentID := c.Param("uuid")
	if _, err := h.Model.GetAgentById(agentID, commonInfo); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "agents.could_not_get_agent"), false))
	}

	allowExtraDNSLabels := false
	if c.FormValue("allow-extra-dns-labels") == "on" {
		allowExtraDNSLabels = true
	}

	p, err := c.FormParams()
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_parse_groups", err.Error()), true))
	}

	groups := ""
	if len(p["groups[]"]) > 0 {
		groupIDs := []string{}
		for _, g := range p["groups[]"] {
			tmp := strings.Split(g, "-")
			if len(tmp) > 1 {
				groupIDs = append(groupIDs, fmt.Sprintf(`"%s"`, tmp[1]))
			}
		}
		groups = strings.Join(groupIDs, ",")
	}

	tenantID, err := strconv.Atoi(commonInfo.TenantID)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "tenants.could_not_convert_to_int", err.Error()), true))
	}

	settings, err := h.Model.GetNetbirdSettings(c.Request().Context(), tenantID)
	if err != nil {
		if ent.IsNotFound(err) {
			settings = &ent.NetbirdSettings{}
		} else {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_get_settings", err.Error()), true))
		}
	}

	if settings.AccessToken == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.token_empty"), true))
	}

	accessToken, err := legacysecret.Open(settings.AccessToken, h.EncryptionMasterKey)
	if err != nil || accessToken == "" {
		return netbirdSettingsFailure(consolesettings.ErrNetbirdSecret)
	}

	groupIDs, err := netbirdapi.ParseGroups(groups)
	if err != nil {
		return netbirdSettingsFailure(consolesettings.ErrNetbirdInvalid)
	}
	setupKey, err := netbirdapi.CreateOneOffKey(c.Request().Context(), h.netbirdHTTPTransport, settings.ManagementURL, accessToken, agentID, groupIDs, allowExtraDNSLabels)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_get_settings", err.Error()), true))
	}

	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := netbirdapi.DeleteKey(cleanupCtx, h.netbirdHTTPTransport, settings.ManagementURL, accessToken, setupKey.ID); err != nil {
			log.Printf("[ERROR]: could not delete one-off key using Netbird API, reason: %v", err)
		}
	}()

	request := nats.NetbirdSettings{
		ManagementURL: settings.ManagementURL,
		OneOffKey:     setupKey.Key,
	}

	data, err := json.Marshal(request)
	if err != nil {
		if strings.Contains(err.Error(), "no responders") {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.agent_offline"), true))
		}
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_create_request", err.Error()), true))
	}

	msg, err := h.RequestBroker("agent.netbird.register."+agentID, data, 1*time.Minute)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.register_request_failed", err.Error()), true))
	}

	result := nats.Netbird{}
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_decode_response", err.Error()), true))
	}

	if result.Error != "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.register_request_failed", result.Error), true))
	}

	if err := h.Model.SaveNetbirdInfo(agentID, result); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_save_data", result.Error), true))
	}

	successMessage := i18n.T(c.Request().Context(), "netbird.register_request_succeeded")

	return h.Netbird(c, successMessage)
}

func (h *Handler) NetbirdUninstall(c echo.Context) error {
	commonInfo, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}

	agentId := c.Param("uuid")

	agent, err := h.Model.GetAgentNetBirdById(agentId, commonInfo)
	if err != nil || agent.Edges.Netbird == nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "agents.could_not_get_agent"), true))
	}

	msg, err := h.RequestBroker("agent.netbird.uninstall."+agentId, nil, 10*time.Minute)
	if err != nil {
		if strings.Contains(err.Error(), "no responders") {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.agent_offline"), true))
		}
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.uninstall_failed", err.Error()), true))
	}

	result := nats.Netbird{}
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_decode_response", err.Error()), true))
	}

	if result.Error != "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.uninstall_failed", result.Error), true))
	}

	if agent.Edges.Netbird.IP != "" {
		if err := h.NetbirdDeletePeer(c, true); err != nil {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.delete_peer_failed", result.Error), true))
		}
	}

	if err := h.Model.SetNetbirdAsUninstalled(agentId); err != nil {
		log.Printf("[INFO]: could not update NetBird data in the database, reason: %v", err)
	}

	successMessage := i18n.T(c.Request().Context(), "netbird.uninstall_succeeded")

	return h.Netbird(c, successMessage)
}

func (h *Handler) NetbirdSwitchProfile(c echo.Context) error {
	commonInfo, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}

	agentID := c.Param("uuid")
	if _, err := h.Model.GetAgentById(agentID, commonInfo); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "agents.could_not_get_agent"), false))
	}

	profile := c.FormValue("profile")
	if profile == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.profile_empty"), true))
	}

	tenantID, err := strconv.Atoi(commonInfo.TenantID)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "tenants.could_not_convert_to_int", err.Error()), true))
	}

	settings, err := h.Model.GetNetbirdSettings(c.Request().Context(), tenantID)
	if err != nil {
		if ent.IsNotFound(err) {
			settings = &ent.NetbirdSettings{}
		} else {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_get_settings", err.Error()), true))
		}
	}

	data, err := json.Marshal(nats.NetbirdSettings{
		Profile:       profile,
		ManagementURL: settings.ManagementURL,
	})

	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_create_request", err.Error()), true))
	}

	msg, err := h.RequestBroker("agent.netbird.switchprofile."+agentID, data, 2*time.Minute)
	if err != nil {
		if strings.Contains(err.Error(), "no responders") {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.agent_offline"), true))
		}
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.profile_switch_failed", err.Error()), true))
	}

	result := nats.Netbird{}
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_decode_response", err.Error()), true))
	}

	if result.Error != "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.profile_switch_failed", result.Error), true))
	}

	if err := h.Model.SaveNetbirdInfo(agentID, result); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_save_data", result.Error), true))
	}

	successMessage := i18n.T(c.Request().Context(), "netbird.profile_switched")

	return h.Netbird(c, successMessage)
}

func (h *Handler) NetbirdRefresh(c echo.Context) error {
	commonInfo, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}

	agentID := c.Param("uuid")
	if _, err := h.Model.GetAgentById(agentID, commonInfo); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "agents.could_not_get_agent"), false))
	}

	msg, err := h.RequestBroker("agent.netbird.refresh."+agentID, nil, 5*time.Minute)
	if err != nil {
		if strings.Contains(err.Error(), "no responders") {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.agent_offline"), true))
		}
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.refresh_failed", err.Error()), true))
	}

	result := nats.Netbird{}
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_decode_response", err.Error()), true))
	}

	if result.Error != "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.refresh_failed", result.Error), true))
	}

	if err := h.Model.SaveNetbirdInfo(agentID, result); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_save_data", result.Error), true))
	}

	successMessage := i18n.T(c.Request().Context(), "netbird.info_refreshed")

	return h.Netbird(c, successMessage)
}

func (h *Handler) NetbirdConnect(c echo.Context) error {
	commonInfo, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}

	agentID := c.Param("uuid")
	if _, err := h.Model.GetAgentById(agentID, commonInfo); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "agents.could_not_get_agent"), false))
	}

	tenantID, err := strconv.Atoi(commonInfo.TenantID)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "tenants.could_not_convert_to_int", err.Error()), true))
	}

	settings, err := h.Model.GetNetbirdSettings(c.Request().Context(), tenantID)
	if err != nil {
		if ent.IsNotFound(err) {
			settings = &ent.NetbirdSettings{}
		} else {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_get_settings", err.Error()), true))
		}
	}

	request := nats.NetbirdSettings{
		ManagementURL: settings.ManagementURL,
	}

	data, err := json.Marshal(request)
	if err != nil {
		if strings.Contains(err.Error(), "no responders") {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.agent_offline"), true))
		}
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_create_request", err.Error()), true))
	}

	msg, err := h.RequestBroker("agent.netbird.up."+agentID, data, 30*time.Second)
	if err != nil {
		if strings.Contains(err.Error(), "no responders") {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.agent_offline"), true))
		}
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.connect_failed", err.Error()), true))
	}

	result := nats.Netbird{}
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_decode_response", err.Error()), true))
	}

	if result.Error != "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.connect_failed", result.Error), true))
	}

	if err := h.Model.SaveNetbirdInfo(agentID, result); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_save_data", result.Error), true))
	}

	successMessage := i18n.T(c.Request().Context(), "netbird.connect_success")

	return h.Netbird(c, successMessage)
}

func (h *Handler) NetbirdDisconnect(c echo.Context, successMessage string) error {
	commonInfo, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}

	agentID := c.Param("uuid")
	if _, err := h.Model.GetAgentById(agentID, commonInfo); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "agents.could_not_get_agent"), false))
	}

	tenantID, err := strconv.Atoi(commonInfo.TenantID)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "tenants.could_not_convert_to_int", err.Error()), true))
	}

	settings, err := h.Model.GetNetbirdSettings(c.Request().Context(), tenantID)
	if err != nil {
		if ent.IsNotFound(err) {
			settings = &ent.NetbirdSettings{}
		} else {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_get_settings", err.Error()), true))
		}
	}

	request := nats.NetbirdSettings{
		ManagementURL: settings.ManagementURL,
	}

	data, err := json.Marshal(request)
	if err != nil {
		if strings.Contains(err.Error(), "no responders") {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.agent_offline"), true))
		}
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_create_request", err.Error()), true))
	}

	msg, err := h.RequestBroker("agent.netbird.down."+agentID, data, 5*time.Minute)
	if err != nil {
		if strings.Contains(err.Error(), "no responders") {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.agent_offline"), true))
		}
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.disconnect_failed", err.Error()), true))
	}

	result := nats.Netbird{}
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_decode_response", err.Error()), true))
	}

	if result.Error != "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.disconnect_failed", result.Error), true))
	}

	if err := h.Model.SaveNetbirdInfo(agentID, result); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_save_data", result.Error), true))
	}

	if successMessage == "" {
		successMessage = i18n.T(c.Request().Context(), "netbird.disconnect_success")
	}

	return h.Netbird(c, successMessage)
}

func (h *Handler) NetbirdDeletePeer(c echo.Context, comingFromUninstall bool) error {
	commonInfo, err := h.GetCommonInfo(c)
	if err != nil {
		return err
	}

	agentID := c.Param("uuid")
	agent, err := h.Model.GetAgentNetBirdById(agentID, commonInfo)

	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "agents.could_not_get_agent"), false))
	}

	tenantID, err := strconv.Atoi(commonInfo.TenantID)
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "tenants.could_not_convert_to_int", err.Error()), true))
	}

	settings, err := h.Model.GetNetbirdSettings(c.Request().Context(), tenantID)
	if err != nil {
		if ent.IsNotFound(err) {
			settings = &ent.NetbirdSettings{}
		} else {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_get_settings", err.Error()), true))
		}
	}

	if settings.AccessToken == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.token_empty"), true))
	}

	accessToken, err := legacysecret.Open(settings.AccessToken, h.EncryptionMasterKey)
	if err != nil || accessToken == "" {
		return netbirdSettingsFailure(consolesettings.ErrNetbirdSecret)
	}

	ip := agent.Edges.Netbird.IP
	if ip == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.empty_ip"), true))
	}

	ipElements := strings.Split(ip, "/")
	if len(ipElements) != 2 {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.wrong_ip_format"), true))
	}

	peerID, err := netbirdapi.PeerIDByIP(c.Request().Context(), h.netbirdHTTPTransport, settings.ManagementURL, accessToken, ipElements[0])
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_get_peer_id", err.Error()), true))
	}

	if err := netbirdapi.DeletePeer(c.Request().Context(), h.netbirdHTTPTransport, settings.ManagementURL, accessToken, peerID); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "netbird.could_not_delete_peer", err.Error()), true))
	}

	if comingFromUninstall {
		return nil
	}
	return h.NetbirdDisconnect(c, i18n.T(c.Request().Context(), "netbird.peer_deleted"))
}
