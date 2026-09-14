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
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestNetbirdRemovalAbsenceViews(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "2", CSRFToken: "owned-netbird-csrf", CurrentVersion: "0.11.0", LatestVersion: "0.11.0"}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/2/computers/90000000-0000-4000-8000-000000000009/netbird/removal-absences", nil).WithContext(ctx), httptest.NewRecorder())
	scope := access.Scope{TenantID: 1, SiteID: 2}
	instant := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	kinds := []string{"review", "review-long", "queued", "delivery-pending", "unconfirmed", "viewer", "stopped", "cancelled", "completed", "released", "history", "history-empty", "history-full", "resolution-withdraw", "resolution-release", "resolution-retry", "resolution-waiting", "resolution-conflict", "resolution-confirm", "resolution-completed", "resolution-released", "resolution-long"}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			info.Principal = access.Principal{UserID: "owned-operator", Grants: []access.Grant{{Role: access.Operator, Scope: scope}}}
			if kind == "viewer" {
				info.Principal.Grants = []access.Grant{{Role: access.Viewer, Scope: scope}}
			}
			target := inventory.ManualTarget{ID: "90000000-0000-4000-8000-000000000009", Name: "Owned <native endpoint>", Platform: "macos", Scope: scope}

			if strings.HasSuffix(kind, "long") {
				target.Name = strings.Repeat("界", 256) + "<native endpoint>"
			}
			r := &inventory.NetbirdRemovalAbsence{ID: "10000000-0000-4000-8000-000000000001", DeviceID: target.ID, Scope: scope, Actor: "Owned <operator>", OriginalID: "60000000-0000-4000-8000-000000000006", Absence: netbirdcommand.RemovalAbsence{Original: netbirdcommand.RemovalAbsenceReference{RequestID: "60000000-0000-4000-8000-000000000006", ReleaseID: "70000000-0000-4000-8000-000000000007", CommandHash: strings.Repeat("f", 64), Revision: strings.Repeat("a", 64)}, Profile: netbirdcommand.RemovalAbsenceProfile, JournalRevision: strings.Repeat("e", 64), StateDigest: strings.Repeat("f", 64)}, AbsenceDigest: strings.Repeat("b", 64), Revision: strings.Repeat("c", 64), RequestedAt: instant, ExpiresAt: instant.Add(2 * time.Minute)}
			status := &inventory.NetbirdRemovalAbsenceStatus{Request: r}
			resolution := &inventory.NetbirdRemovalAbsenceResolution{ID: "20000000-0000-4000-8000-000000000002", RequestID: r.ID, Actor: r.Actor, Kind: "withdraw", CreatedAt: instant, LastAttempt: &inventory.NetbirdRemovalAbsenceControlAttempt{ID: "40000000-0000-4000-8000-000000000004", Actor: r.Actor, Kind: "withdraw", Sequence: 1, CreatedAt: instant, Outcome: "unavailable"}}
			var component templ.Component
			switch {
			case strings.HasPrefix(kind, "review"):
				component = NetbirdRemovalAbsenceReview(c, info, &inventory.NetbirdRemovalAbsenceReview{Target: target, Absence: r.Absence, AbsenceDigest: r.AbsenceDigest, Revision: r.Revision}, r.ID)
			case strings.HasPrefix(kind, "history"):
				page := &inventory.NetbirdRemovalAbsenceHistory{Requests: []*inventory.NetbirdRemovalAbsenceStatus{status}}
				if kind == "history-empty" {
					page.Requests = nil
				}
				if kind == "history-full" {
					page.Next = r.ID
					for range 19 {
						page.Requests = append(page.Requests, status)
					}
				}
				component = NetbirdRemovalAbsenceHistory(c, info, scope, target.ID, page)
			case strings.HasPrefix(kind, "resolution"):
				expiry := instant.Add(2 * time.Minute)
				v := &inventory.NetbirdRemovalAbsenceResolutionReview{RequestID: r.ID, ResolutionID: resolution.ID, Revision: strings.Repeat("d", 64), ExpiresAt: &expiry, Kind: "withdraw", Outcome: "not-received"}
				switch kind {
				case "resolution-release":
					v.Kind = "release"
					v.Outcome = "unconfirmed"
				case "resolution-retry":
					v.Kind = "release"
					v.Outcome = "unconfirmed"
					v.Resolution = resolution
				case "resolution-waiting", "resolution-conflict", "resolution-completed", "resolution-released":
					v.Kind = ""
					v.Revision = ""
					v.Outcome = strings.TrimPrefix(kind, "resolution-")
					v.ExpiresAt = nil
				case "resolution-confirm":
					v.Kind = ""
					v.Revision = ""
					v.Outcome = "awaiting-confirmation"
					v.ExpiresAt = nil
					v.Resolution = resolution
				case "resolution-long":
					r.Actor = strings.Repeat("界", 255)
					resolution.Actor = r.Actor
					v.Resolution = resolution
				}
				component = NetbirdRemovalAbsenceResolution(c, info, status, v)
			default:
				if kind == "delivery-pending" || kind == "unconfirmed" || kind == "viewer" || kind == "completed" || kind == "released" {
					status.Delivery = &inventory.NetbirdRemovalAbsenceDelivery{RequestID: r.ID, CommandHash: strings.Repeat("e", 64), IssuedAt: instant, ExpiresAt: instant.Add(2 * time.Minute), Outcome: "unconfirmed", OriginalOutcome: "unconfirmed"}
					if kind == "delivery-pending" {
						status.Delivery.Outcome = "pending"
						status.Delivery.OriginalOutcome = "pending"
					}
				}
				if kind == "completed" {
					r.CompletedAt = &instant
					status.Delivery.CompletedAt = &instant
				}
				if kind == "released" {
					r.ReleasedAt = &instant
					r.ReleasedBy = r.Actor
					r.ResolutionID = resolution.ID
					status.Resolution = resolution
				}
				if kind == "cancelled" {
					r.CancelledAt = &instant
					r.CancelledBy = r.Actor
				}
				if kind == "stopped" {
					status.DispatchStop = &inventory.NetbirdRemovalAbsenceDispatchStop{RequestID: r.ID, Reason: "source_changed", RecordedAt: instant}
				}
				component = NetbirdRemovalAbsenceReceipt(c, info, status, "50000000-0000-4000-8000-000000000005")
			}
			var body bytes.Buffer
			body.WriteString(`<!doctype html><html class="uk-theme-openuem"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"><script src="/assets/js/htmx.min.js" defer></script><script src="/assets/js/timestamps.js" defer></script></head><body class="bg-background text-foreground"><main id="main">`)
			require.NoError(t, component.Render(ctx, &body))
			body.WriteString("</main></body></html>")
			text := body.String()
			actions := text[strings.Index(text, `<section class="netbird-operations`):]
			require.Equal(t, 1, strings.Count(text, `id="netbird-operation-heading"`))
			require.NotContains(t, text, "<native endpoint>")
			require.NotContains(t, text, "<operator>")
			require.NotContains(t, text, "source_url")
			require.NotContains(t, text, "certificate_hash")
			if strings.HasPrefix(kind, "review") {
				require.Contains(t, text, "This check reads the current state. It cannot remove files or stop processes.")
				require.Contains(t, text, "does not confirm that the original uninstall succeeded")
				require.NotContains(t, text, "Package version")
			}
			if kind == "viewer" {
				require.NotContains(t, actions, "<form")
				require.NotContains(t, text, "Review verification resolution")
			}
			if kind == "completed" || kind == "released" || kind == "cancelled" {
				require.NotContains(t, actions, "<form")
			}
			if strings.HasPrefix(kind, "review") || strings.HasPrefix(kind, "resolution-") && strings.Contains(text, `id="netbird-submit"`) {
				require.Contains(t, text, `name="confirmed" value="yes" required`)
				require.NotContains(t, text, " checked")
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "netbird-removal-absences-"+kind+".html"), body.Bytes(), 0600))
			}
		})
	}
}
