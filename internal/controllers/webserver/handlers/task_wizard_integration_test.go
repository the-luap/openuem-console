package handlers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/utils"
	"github.com/stretchr/testify/require"
)

func exerciseTaskWizardScope(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site int) {
	t.Helper()
	request := ownedTagHTTPRequest(t, h, e, ctx)
	for old, value := range map[string]string{"task-types": "task-agent-type=windows", "task-subtypes": "task-type=package_type", "task-definition": "task-subtype=netbird_install"} {
		require.Equal(t, 410, request("apple-console-admin", "GET", "/profiles/"+old+"?"+value, nil, "").Code)
	}
	var calls atomic.Int64
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		require.Equal(t, "/api/groups", r.URL.Path)
		require.Equal(t, "Token owned-wizard-token", r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `[{"id":"group-ID-1","name":"Owned <provider-group>","peers_count":2}]`)
	}))
	defer provider.Close()
	previousTransport, previousKey := h.netbirdHTTPTransport, h.EncryptionMasterKey
	h.netbirdHTTPTransport = provider.Client().Transport
	h.EncryptionMasterKey = strings.Repeat("k", 32)
	defer func() { h.netbirdHTTPTransport = previousTransport; h.EncryptionMasterKey = previousKey }()
	encrypted, err := utils.EncryptSensitiveField("owned-wizard-token", h.EncryptionMasterKey)
	require.NoError(t, err)
	settings, err := h.Model.Client.NetbirdSettings.Create().SetManagementURL(provider.URL).SetAccessToken(encrypted).AddTenantIDs(tenant).Save(ctx)
	require.NoError(t, err)
	defer func() {
		// This legacy FK cascades tenant deletion when settings are removed. Detach
		// the owned fixture first, preserving the shared route-test tenant.
		_, err := h.Model.DB.ExecContext(ctx, "UPDATE tenants SET tenant_netbird=NULL WHERE id=$1 AND tenant_netbird=$2", tenant, settings.ID)
		require.NoError(t, err)
		require.NoError(t, h.Model.Client.NetbirdSettings.DeleteOneID(settings.ID).Exec(ctx))
	}()
	for _, scope := range []access.Scope{{}, {TenantID: tenant}, {TenantID: tenant, SiteID: site}} {
		prefix := ""
		create := h.Model.Client.Profile.Create().SetName("Owned wizard profile")
		if scope.TenantID != 0 {
			create.AddTenantIDs(tenant)
			prefix = fmt.Sprintf("/tenant/%d", tenant)
		}
		if scope.SiteID != 0 {
			create.AddSiteIDs(site)
			prefix += fmt.Sprintf("/site/%d", site)
		}
		p, err := create.Save(ctx)
		require.NoError(t, err)
		defer h.Model.Client.Profile.DeleteOneID(p.ID).Exec(ctx)
		base := fmt.Sprintf("%s/tasks/%d/new", prefix, p.ID)
		for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
			before := calls.Load()
			require.Equal(t, 403, request(actor, "GET", base+"/definition?task-subtype=netbird_register", nil, "").Code)
			require.Equal(t, before, calls.Load())
		}
		for stage, value := range map[string]string{"types": "task-agent-type=windows", "subtypes": "task-type=package_type", "definition": "task-subtype=add_registry_key"} {
			w := request("apple-console-admin", "GET", base+"/"+stage+"?"+value, nil, "")
			require.Equal(t, 200, w.Code)
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			require.NotContains(t, w.Body.String(), "MISSING")
			if stage == "types" {
				require.Contains(t, w.Body.String(), base+"/subtypes")
			}
			if stage == "subtypes" {
				require.Contains(t, w.Body.String(), base+"/definition")
			}
			for _, bad := range []string{value + "&profile=1", value + "&" + value, value + "&task-description=private", strings.Repeat("x", 513)} {
				require.Equal(t, 400, request("apple-console-admin", "GET", base+"/"+stage+"?"+bad, nil, "").Code)
			}
		}
		w := request("apple-console-admin", "GET", base+"/subtypes?task-type=powershell_type", nil, "")
		require.Equal(t, 200, w.Code)
		require.Equal(t, "#task-definition", w.Header().Get("HX-Retarget"))
		require.Contains(t, w.Body.String(), "powershell-script")
		before := calls.Load()
		w = request("apple-console-admin", "GET", base+"/definition?task-subtype=netbird_register", nil, "")
		if scope.TenantID == 0 {
			require.Equal(t, 409, w.Code)
			require.Equal(t, before, calls.Load())
		} else {
			require.Equal(t, 200, w.Code)
			require.Equal(t, before+1, calls.Load())
			require.Contains(t, w.Body.String(), "Owned &lt;provider-group&gt;")
			require.Contains(t, w.Body.String(), `value="group-ID-1"`)
			require.NotContains(t, w.Body.String(), "owned-wizard-token")
			require.NotContains(t, w.Body.String(), encrypted)
			before = calls.Load()
			require.Equal(t, 404, request("apple-console-admin", "GET", fmt.Sprintf("/tasks/%d/new/definition?task-subtype=netbird_register", p.ID), nil, "").Code)
			require.Equal(t, before, calls.Load())
		}
	}
}
