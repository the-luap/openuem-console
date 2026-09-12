package mdm_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/a-h/templ"
	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestAppleUpdateSchedulePages(t *testing.T) {
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "owned-operator")
	scope := access.Scope{TenantID: 1, SiteID: 1}
	for _, state := range []string{"scheduled", "waiting", "activated", "blocked", "expired", "canceled", "history", "empty-history", "long", "organization-scheduled", "organization-waiting", "organization-activated", "organization-blocked", "organization-expired", "organization-canceled", "organization-history", "organization-empty-history", "organization-long", "organization-site-operator", "organization-reader"} {
		t.Run(state, func(t *testing.T) {
			fixture := state
			organization := strings.HasPrefix(state, "organization-")
			state := strings.TrimPrefix(state, "organization-")
			info := &partials.CommonInfo{Principal: access.Principal{UserID: "owned-operator", Grants: []access.Grant{{Role: access.Operator, Scope: scope}}}, SM: &sessions.SessionManager{Manager: sm}, CSRFToken: "owned-csrf", TenantID: "1", SiteID: "1", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Owned organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
			if organization && state != "site-operator" && state != "reader" {
				info.Principal.Grants = []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}
			}
			if state == "reader" {
				info.Principal.Grants = []access.Grant{{Role: access.Viewer, Scope: scope}}
			}
			now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
			r := apple.UpdateSchedule{GroupScope: apple.Scope{TenantID: 1, SiteID: 1}, ID: "80000000-0000-0000-0000-000000000001", Scope: apple.Scope{TenantID: 1, SiteID: 1}, RequestKey: "50000000-0000-0000-0000-000000000001", Actor: "owned-operator", ActorRevision: 1, CreatedAt: now, NotBefore: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour), UpdatedAt: now, NextAttemptAt: now.Add(time.Hour), Phase: state, Revision: 1, Targets: []apple.UpdatePlanGroupSelection{{DeviceID: "10000000-0000-0000-0000-000000000001", PolicyToken: strings.Repeat("a", 64)}}}
			if organization {
				r.GroupScope.SiteID = 0
			}
			if state == "site-operator" || state == "reader" {
				r.Phase = "scheduled"
			}
			r.Plan = apple.UpdatePlan{ID: "70000000-0000-0000-0000-000000000001", Scope: r.Scope, Revision: 2, Actor: "owned-operator", CreatedAt: now, Definition: apple.UpdatePlanDefinition{Name: "Owned <scheduled pilot>", Description: "Reviewed update", Platform: "ios", TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: "2026-10-01T18:00:00", DetailsURL: "https://example.test/update"}}
			r.Group = apple.ProfileGroupSource{ID: "30000000-0000-0000-0000-000000000001", Revision: 3, Name: "Owned <scheduled group>", Rule: inventory.DeviceGroupRule{Search: "Owned"}}
			switch state {
			case "waiting":
				r.Reason = "temporarily_unavailable"
				r.Revision = 2
				r.Attempts = 1
			case "activated":
				r.AssignmentID = "40000000-0000-0000-0000-000000000001"
				r.Revision = 2
				r.Attempts = 1
				r.UpdatedAt = r.NotBefore
				r.CompletedAt = &r.UpdatedAt
			case "blocked":
				r.Reason = "review_changed"
			case "expired":
				r.Reason = "activation_window_expired"
			case "canceled":
				r.Reason = "canceled_by_operator"
			case "long":
				r.Phase = "blocked"
				r.Reason = "authority_changed"
				r.Actor = strings.Repeat("A", 240) + "<script>"
				r.Plan.Definition.Name = strings.Repeat("P", 110) + "<script>"
				r.Group.Name = strings.Repeat("G", 110) + "<script>"
			}
			c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/ios/update-plans/"+r.Plan.ID+"/schedules", nil).WithContext(ctx), httptest.NewRecorder())
			var component templ.Component
			if state == "history" || state == "empty-history" {
				r.Phase = "scheduled"
				items := []apple.UpdateSchedule{r}
				next := r.ID
				if state == "empty-history" {
					items = nil
					next = ""
				}
				component = AppleUpdateSchedules(c, info, r.Plan.ID, items, next)
			} else {
				component = AppleUpdateSchedule(c, info, r)
			}
			var body bytes.Buffer
			require.NoError(t, component.Render(ctx, &body))
			html := body.String()
			require.NotContains(t, html, "<script>"+r.Actor)
			require.NotContains(t, html, r.Plan.Definition.Name)
			require.NotContains(t, html, "@CSRF")
			require.NotContains(t, html, r.Targets[0].PolicyToken)
			require.Equal(t, state == "scheduled" || state == "waiting" || state == "site-operator", strings.Contains(html, "data-update-schedule-cancel"))
			require.Equal(t, state == "activated", strings.Contains(html, "Open activation receipt"))
			if organization && state != "empty-history" {
				if state == "history" {
					require.Contains(t, html, "Source: organization group · Target site: 1")
				} else {
					require.Contains(t, html, "Only the selected target site's members")
					require.NotContains(t, html, `href="/tenant/1/site/1/device-groups/`+r.Group.ID+`"`)
					require.Equal(t, state != "site-operator" && state != "reader", strings.Contains(html, `href="/tenant/1/device-groups/`+r.Group.ID+`"`))
				}
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "apple-update-schedule-"+fixture+".html"), body.Bytes(), 0644))
			}
		})
	}
}
