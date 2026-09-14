package admin_views

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/a-h/templ"
	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestNetbirdPackageViews(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "-1", CSRFToken: "owned-netbird-csrf", CurrentVersion: "0.11.0", LatestVersion: "0.11.0"}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/netbird/packages", nil).WithContext(ctx), httptest.NewRecorder())
	for _, kind := range []string{"new", "empty", "list", "list-viewer", "detail", "detail-viewer", "revoked", "long"} {
		info.Principal = access.Principal{UserID: "owned-admin", Grants: []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}}
		if strings.Contains(kind, "viewer") {
			info.Principal.Grants[0].Role = access.Viewer
		}
		p := inventory.NetbirdPackageApproval{ID: "10000000-0000-4000-8000-000000000001", TenantID: 1, Actor: "Owned administrator", Platform: "linux", Architecture: "arm64", Format: "deb", PackageID: "netbird", Version: "0.78.1", Size: 1234, SHA256: strings.Repeat("a", 64), Digest: strings.Repeat("b", 64), Verification: "Owned signing review 42", CreatedAt: time.Date(2026, 9, 14, 8, 0, 0, 0, time.UTC)}
		if kind == "revoked" {
			at := p.CreatedAt.Add(time.Hour)
			p.RevokedAt = &at
			p.RevokedBy = "Owned administrator"
			p.RevocationID = "20000000-0000-4000-8000-000000000002"
		}
		if kind == "long" {
			p.Verification = strings.Repeat("Review_", 70) + "<Berlin>"
			p.Actor = strings.Repeat("Admin", 45)
			p.Version = strings.Repeat("v", 128)
		}
		var cmp templ.Component
		switch kind {
		case "new":
			cmp = NetbirdPackageNew(c, info, p.ID)
		case "empty":
			cmp = NetbirdPackageList(c, info, &inventory.NetbirdPackagePage{})
		case "list", "list-viewer":
			cmp = NetbirdPackageList(c, info, &inventory.NetbirdPackagePage{Approvals: []inventory.NetbirdPackageApproval{p}, Next: p.ID})
		default:
			cmp = NetbirdPackageDetail(c, info, &p, "20000000-0000-4000-8000-000000000002")
		}
		var body bytes.Buffer
		body.WriteString(`<!doctype html><html lang="en" class="uk-theme-openuem"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"><script src="/assets/js/htmx.min.js" defer></script></head><body class="bg-background text-foreground"><div id="main">`)
		require.NoError(t, cmp.Render(ctx, &body))
		body.WriteString(`</div></body></html>`)
		html := body.String()
		require.NotContains(t, html, "@mdm_views")
		require.NotContains(t, html, "MISSING")
		require.NotContains(t, html, "<Berlin>")
		if kind == "detail-viewer" || kind == "revoked" {
			require.NotContains(t, html, `id="netbird-package-revoke"`)
		}
		if directory := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); directory != "" {
			require.NoError(t, os.MkdirAll(directory, 0755))
			require.NoError(t, os.WriteFile(filepath.Join(directory, "netbird-packages-"+kind+".html"), body.Bytes(), 0600))
		}
	}
}
