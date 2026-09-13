package desktop_views

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
	nats "github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestNetbirdOperationViews(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "2", CSRFToken: "owned-netbird-csrf", CurrentVersion: "0.11.0", LatestVersion: "0.11.0"}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/2/computers/owned-device/netbird", nil).WithContext(ctx), httptest.NewRecorder())
	scope := access.Scope{TenantID: 1, SiteID: 2}
	instant := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	for _, kind := range []string{"overview", "overview-empty", "overview-long", "overview-viewer", "review-up", "review-down", "review-switch", "review-long", "queued", "sending", "completed", "stopped", "unconfirmed", "released", "history", "history-empty"} {
		t.Run(kind, func(t *testing.T) {
			info.Principal = access.Principal{UserID: "owned-admin", Grants: []access.Grant{{Role: access.Administrator}}}
			if kind == "overview-viewer" {
				info.Principal.Grants = []access.Grant{{Role: access.Viewer, Scope: scope}}
			}
			target := inventory.ManualTarget{ID: "owned-device", Name: "Owned <NetBird endpoint>", Platform: "linux", Scope: scope}
			name := "Office <Berlin>"
			profile := "owned-profile"
			management := "https://management.example.test"
			if strings.HasSuffix(kind, "long") {
				target.Name = strings.Repeat("界", 256)
				name = strings.Repeat("W", 256)
				profile = strings.Repeat("p", 256)
				management += "/" + strings.Repeat("m", 1800)
			}
			var component templ.Component
			switch {
			case strings.HasPrefix(kind, "overview"):
				page := &inventory.NetbirdOverview{Target: target, Installed: true, ManagementConnected: true, Profile: name, Profiles: []nats.NetbirdProfile{{ID: profile, Name: name, Active: true}}, ManagementURL: management, Version: "owned-version", LastContact: &instant}
				if kind == "overview-empty" {
					page.Profiles = nil
				}
				component = NetbirdOverview(c, info, page, "10000000-0000-4000-8000-000000000003")
			case strings.HasPrefix(kind, "review"):
				operation := "switchprofile"
				if kind == "review-up" {
					operation = "up"
				}
				if kind == "review-down" {
					operation = "down"
				}
				if operation != "switchprofile" {
					profile = ""
					name = ""
				}
				component = NetbirdReview(c, info, &inventory.NetbirdOperationReview{Target: target, Operation: operation, Profile: profile, ProfileName: name, ManagementURL: management, Revision: strings.Repeat("a", 64)}, "10000000-0000-4000-8000-000000000001")
			case strings.HasPrefix(kind, "history"):
				var rows []inventory.NetbirdOperation
				if kind != "history-empty" {
					rows = []inventory.NetbirdOperation{{ID: "10000000-0000-4000-8000-000000000001", DeviceID: target.ID, Operation: "up", Status: "completed", RequestedAt: instant}, {ID: "10000000-0000-4000-8000-000000000002", DeviceID: target.ID, Operation: "down", Status: "unconfirmed", RequestedAt: instant}}
				}
				component = NetbirdHistory(c, info, target.ID, rows)
			default:
				r := &inventory.NetbirdOperation{ID: "10000000-0000-4000-8000-000000000001", DeviceID: target.ID, Scope: scope, Operation: "up", Status: kind, RequestedAt: instant, ExpiresAt: instant.Add(2 * time.Minute)}
				if kind == "sending" {
					r.Status = "queued"
					r.AttemptedAt = &instant
				}
				if kind == "unconfirmed" || kind == "released" {
					r.Status = "unconfirmed"
					r.Reason = "delivery_unconfirmed"
					r.AttemptedAt = &instant
				}
				if kind == "released" {
					r.ReleasedAt = &instant
				}
				if kind == "stopped" {
					r.Reason = "source_changed"
				}
				component = NetbirdReceipt(c, info, r)
			}
			var body bytes.Buffer
			body.WriteString(`<!doctype html><html class="uk-theme-openuem"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"><script src="/assets/js/htmx.min.js" defer></script><script src="/assets/js/timestamps.js" defer></script></head><body class="bg-background text-foreground"><main id="main">`)
			require.NoError(t, component.Render(ctx, &body))
			body.WriteString("</main></body></html>")
			html := body.String()
			require.Equal(t, 1, strings.Count(html, `id="netbird-operation-heading"`))
			require.NotContains(t, html, "<Berlin>")
			if strings.HasPrefix(kind, "review") {
				require.Contains(t, html, `name="confirmed" value="yes" required`)
				require.Contains(t, html, `name="revision" value="`+strings.Repeat("a", 64)+`"`)
				require.NotContains(t, html, " checked")
			}
			if kind == "overview-viewer" {
				require.NotContains(t, html, "Review connect")
				require.NotContains(t, html, "Review profile switch")
			}
			if kind == "unconfirmed" || kind == "released" {
				require.Contains(t, html, "Execution is unconfirmed.")
				require.NotContains(t, html, "Command execution confirmed.")
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "netbird-operations-"+kind+".html"), body.Bytes(), 0600))
			}
		})
	}
}
