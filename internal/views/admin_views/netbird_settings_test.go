package admin_views

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	consolesettings "github.com/open-uem/openuem-console/internal/settings"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestNetbirdSettingsViews(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "-1", CSRFToken: "owned-netbird-csrf", CurrentVersion: "0.11.0", LatestVersion: "0.11.0"}
	base := "/tenant/1/admin/netbird"
	c := echo.New().NewContext(httptest.NewRequest("GET", base, nil).WithContext(ctx), httptest.NewRecorder())
	for _, kind := range []string{"new", "configured", "empty", "shared", "saved", "long"} {
		review := &consolesettings.NetbirdReview{ID: 17, Revision: strings.Repeat("a", 64), ManagementURL: "https://provider.example.invalid/management", TokenSet: true}
		switch kind {
		case "new":
			review.ID = 0
			review.TokenSet = false
		case "empty":
			review.TokenSet = false
		case "shared":
			review.Shared = true
		case "long":
			review.ManagementURL = "https://" + strings.Repeat("w", 63) + ".example.invalid/" + strings.Repeat("long-prefix/", 120)
		}
		var body bytes.Buffer
		body.WriteString("<!doctype html><html lang=\"en\" class=\"uk-theme-openuem\"><head><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"stylesheet\" href=\"/assets/css/main.css\"><script src=\"/assets/js/htmx.min.js\" defer></script></head><body class=\"bg-background text-foreground\"><div id=\"main\">")
		require.NoError(t, NetbirdSettings(c, review, info, base, kind == "saved").Render(ctx, &body))
		body.WriteString("</div></body></html>")
		html := body.String()
		require.Contains(t, html, "Stored tokens are never shown")
		require.Contains(t, html, "name=\"csrf\" value=\"owned-netbird-csrf\"")
		require.NotContains(t, html, "@cmp")
		require.NotContains(t, html, "MISSING")
		if kind == "shared" {
			require.Contains(t, html, "separate copy for this organization")
		}
		if directory := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); directory != "" {
			require.NoError(t, os.MkdirAll(directory, 0755))
			require.NoError(t, os.WriteFile(filepath.Join(directory, "netbird-settings-"+kind+".html"), body.Bytes(), 0600))
		}
	}
}
