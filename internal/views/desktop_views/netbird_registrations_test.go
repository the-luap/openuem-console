package desktop_views

import (
	"bytes"
	"fmt"
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
	"github.com/open-uem/nats/netbirdapi"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestNetbirdRegistrationViews(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "2", CSRFToken: "owned-netbird-csrf", CurrentVersion: "0.11.0", LatestVersion: "0.11.0"}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/2/computers/owned-device/netbird/registrations", nil).WithContext(ctx), httptest.NewRecorder())
	scope := access.Scope{TenantID: 1, SiteID: 2}
	instant := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	for _, kind := range []string{"cleanup-ready", "cleanup-retry", "cleanup-long", "cleanup-absent", "cleanup-retained", "cleanup-changed", "cleanup-unavailable", "choices", "choices-empty", "choices-long", "review", "review-empty", "review-long", "queued", "started", "completed", "stopped", "unconfirmed-create", "unconfirmed-delivery", "unconfirmed-cleanup", "unconfirmed-cleaned", "unconfirmed-viewer", "history", "history-empty", "history-full", "unconfirmed-resolved", "history-resolved", "resolution-completed", "resolution-release", "resolution-cleanup", "resolution-no-delivery", "resolution-continue", "resolution-pending", "resolution-confirmed", "resolution-unknown-key", "resolution-missing-receipt", "resolution-active", "resolution-changed-key", "resolution-unavailable", "resolution-long", "resolution-withdraw", "resolution-withdraw-cleanup", "resolution-withdrawn", "resolution-recovery-unavailable", "resolution-retry-release", "resolution-retry-withdraw", "resolution-retry-long"} {
		t.Run(kind, func(t *testing.T) {
			info.Principal = access.Principal{UserID: "owned-admin", Grants: []access.Grant{{Role: access.Administrator}}}
			if kind == "unconfirmed-viewer" {
				info.Principal.Grants = []access.Grant{{Role: access.Viewer, Scope: scope}}
			}
			target := inventory.ManualTarget{ID: "owned-device", Name: "Owned <NetBird endpoint>", Platform: "linux", Scope: scope}
			choice := nats.NetBirdGroups{ID: "owned-group", Name: "Office <Berlin>"}
			management := "https://management.example.test"
			if strings.HasSuffix(kind, "long") {
				target.Name = strings.Repeat("界", 256)
				choice.Name = strings.Repeat("W", 1024)
				choice.ID = strings.Repeat("g", 128)
				management += "/" + strings.Repeat("m", 1800)
			}
			review := &inventory.NetbirdRegistrationReview{Target: target, ManagementURL: management, GroupChoices: []nats.NetBirdGroups{choice, {ID: "other-group", Name: "Another group"}}, Groups: []string{choice.ID}, ExtraDNS: true, Revision: strings.Repeat("a", 64)}
			if strings.HasSuffix(kind, "empty") {
				review.Groups = nil
				review.GroupChoices = nil
				review.ExtraDNS = false
			}
			var component templ.Component
			switch {
			case strings.HasPrefix(kind, "cleanup-"):
				r := &inventory.NetbirdRegistration{ID: "10000000-0000-4000-8000-000000000001", DeviceID: target.ID, Scope: scope, Status: "unconfirmed", Key: &netbirdapi.ManagedKeyMetadata{ID: choice.ID}, Attempts: []string{"create", "deliver", "delete"}}
				v := &inventory.NetbirdCleanupReview{Registration: r, Target: target, ManagementURL: management, Revision: strings.Repeat("a", 64), KeyState: "present", CanRetry: true}
				if kind != "cleanup-ready" {
					r.LastCleanupRetry = &inventory.NetbirdCleanupRetry{ID: "50000000-0000-4000-8000-000000000005", Actor: "Owned <reviewer>", Sequence: 2, CreatedAt: instant}
				}
				switch kind {
				case "cleanup-absent":
					v.KeyState = "absent"
					v.CanRetry = false
				case "cleanup-retained":
					v.KeyState = "absent"
					v.CanRetry = false
					r.KeyAbsent = true
				case "cleanup-changed":
					v.KeyState = "changed"
					v.CanRetry = false
				case "cleanup-unavailable":
					v.KeyState = "unavailable"
					v.CanRetry = false
				case "cleanup-long":
					r.LastCleanupRetry.Actor = strings.Repeat("W", 255)
				}
				component = NetbirdCleanupReview(c, info, v, "30000000-0000-4000-8000-000000000003")
			case strings.HasPrefix(kind, "choices"):
				component = NetbirdRegistrationChoices(c, info, review)
			case strings.HasPrefix(kind, "review"):
				component = NetbirdRegistrationReview(c, info, review, "10000000-0000-4000-8000-000000000001")
			case strings.HasPrefix(kind, "history"):
				rows := []inventory.NetbirdRegistration{}
				count := 2
				if kind == "history-empty" {
					count = 0
				}
				if kind == "history-full" {
					count = 50
				}
				for index := 0; index < count; index++ {
					rows = append(rows, inventory.NetbirdRegistration{ID: fmt.Sprintf("10000000-0000-4000-8000-%012d", index+1), DeviceID: target.ID, Status: "completed", RequestedAt: instant})
				}
				if kind == "history-resolved" {
					rows[0].Status = "unconfirmed"
					rows[0].ReleasedAt = &instant
				}
				component = NetbirdRegistrationHistory(c, info, target.ID, rows)
			case strings.HasPrefix(kind, "resolution-"):
				r := &inventory.NetbirdRegistration{ID: "10000000-0000-4000-8000-000000000001", DeviceID: target.ID, Scope: scope, Status: "unconfirmed", KeyAbsent: true}
				v := &inventory.NetbirdRegistrationResolutionReview{Registration: r, Target: target, Revision: strings.Repeat("a", 64), KeyState: "absent", AgentState: "completed", CanResolve: true}
				d := &inventory.NetbirdRegistrationResolution{ID: "20000000-0000-4000-8000-000000000002", RequestID: r.ID, Actor: "Owned <operator>", CreatedAt: instant, Kind: "release"}
				switch kind {
				case "resolution-release":
					v.AgentState = "unconfirmed"
				case "resolution-cleanup":
					v.AgentState = "unconfirmed"
					v.KeyState = "present"
					v.CanCleanup = true
					r.KeyAbsent = false
				case "resolution-no-delivery":
					v.AgentState = "not-attempted"
				case "resolution-continue":
					v.Resolution = d
					v.CanResolve = false
					v.CanContinue = true
					v.AgentState = "unconfirmed"
				case "resolution-pending":
					v.Resolution = d
					d.AgentAttemptedAt = &instant
					v.CanResolve = false
					v.AgentState = "unconfirmed"
				case "resolution-confirmed":
					v.Resolution = d
					d.ConfirmedAt = &instant
					d.ConfirmedBy = "Owned <manager>"
					r.ReleasedAt = &instant
					v.CanResolve = false
					v.AgentState = "resolved"
				case "resolution-unknown-key":
					v.KeyState = "unknown"
					r.KeyAbsent = false
					v.CanResolve = false
				case "resolution-missing-receipt":
					v.AgentState = "missing"
					v.CanResolve = false
				case "resolution-active":
					v.AgentState = "waiting"
					v.CanResolve = false
				case "resolution-changed-key":
					v.KeyState = "changed"
					r.KeyAbsent = false
					v.CanResolve = false
				case "resolution-unavailable":
					v.KeyState = "unavailable"
					v.AgentState = "unavailable"
					r.KeyAbsent = false
					v.CanResolve = false
				case "resolution-withdraw":
					v.AgentState = "not-received"
				case "resolution-withdraw-cleanup":
					v.AgentState = "not-received"
					v.KeyState = "present"
					v.CanCleanup = true
					r.KeyAbsent = false
				case "resolution-withdrawn":
					v.AgentState = "withdrawn"
					v.Resolution = d
					d.Kind = "withdraw"
					d.AgentAttemptedAt = &instant
					v.CanResolve = false
				case "resolution-recovery-unavailable":
					v.AgentState = "recovery-unavailable"
					v.CanResolve = false
				case "resolution-retry-release", "resolution-retry-withdraw", "resolution-retry-long":
					v.Resolution = d
					v.CanResolve = false
					v.CanRetry = true
					v.RetryKind = "release"
					v.AgentState = "unconfirmed"
					d.AgentAttemptedAt = &instant
					if kind == "resolution-retry-withdraw" {
						v.RetryKind = "withdraw"
						v.AgentState = "not-received"
						d.Kind = "withdraw"
					}
					d.LastRetry = &inventory.NetbirdResolutionRetry{ID: "50000000-0000-4000-8000-000000000005", Actor: "Owned <reviewer>", Kind: v.RetryKind, Sequence: 2, CreatedAt: instant}
					if strings.HasSuffix(kind, "long") {
						d.LastRetry.Actor = strings.Repeat("W", 255)
					}
				case "resolution-long":
					v.Resolution = d
					v.CanResolve = false
					v.CanContinue = true
					d.Actor = strings.Repeat("W", 255)
				}
				component = NetbirdRegistrationResolution(c, info, v, "30000000-0000-4000-8000-000000000003")
			default:
				r := &inventory.NetbirdRegistration{ID: "10000000-0000-4000-8000-000000000001", DeviceID: target.ID, Scope: scope, Actor: "Owned <operator>", Status: kind, RequestedAt: instant, ExpiresAt: instant.Add(2 * time.Minute), Groups: review.Groups, ExtraDNS: true}
				if kind == "started" {
					r.Status = "queued"
					r.Attempts = []string{"create"}
				}
				if kind == "stopped" {
					r.Reason = "source_changed"
					r.FinishedAt = &instant
				}
				if kind == "completed" || strings.HasPrefix(kind, "unconfirmed") {
					r.Status = "unconfirmed"
					r.Reason = "registration_unconfirmed"
					r.FinishedAt = &instant
					r.Attempts = []string{"create"}
					if kind != "unconfirmed-create" {
						r.Key = &netbirdapi.ManagedKeyMetadata{ID: "owned-key-id", ExpiresAt: instant.Add(24 * time.Hour)}
						r.Attempts = append(r.Attempts, "deliver")
					}
					if kind == "unconfirmed-cleanup" || kind == "unconfirmed-cleaned" || kind == "unconfirmed-viewer" || kind == "completed" {
						r.Attempts = append(r.Attempts, "delete")
						r.Delivered = &inventory.NetbirdOperationResult{Success: true}
					}
					if kind == "unconfirmed-cleaned" || kind == "unconfirmed-resolved" || kind == "completed" {
						r.KeyAbsent = true
					}
					if kind == "completed" {
						r.Status = "completed"
						r.Reason = ""
					}
				}
				if kind == "unconfirmed-resolved" {
					r.ReleasedAt = &instant
					r.ReleasedBy = "Owned <manager>"
					r.Resolution = &inventory.NetbirdRegistrationResolution{ID: "20000000-0000-4000-8000-000000000002"}
				}
				component = NetbirdRegistrationReceipt(c, info, r)
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
				require.NotContains(t, html, " checked")
			}
			if kind == "unconfirmed-viewer" {
				require.NotContains(t, html, `id="netbird-cleanup"`)
				require.NotContains(t, html, `id="netbird-cleanup-review-link"`)
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "netbird-registrations-"+kind+".html"), body.Bytes(), 0600))
			}
		})
	}
}
