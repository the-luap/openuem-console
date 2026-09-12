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

func TestAppleUpdateGroupPages(t *testing.T) {
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "owned-operator")
	scope := access.Scope{TenantID: 1, SiteID: 1}

	for _, state := range []string{"choose", "empty", "preview", "existing", "excluded", "assignment", "history", "empty-history", "long", "organization-choose", "organization-empty", "organization-preview", "organization-existing", "organization-excluded", "organization-assignment", "organization-history", "organization-progress", "organization-receipt-site-operator", "organization-preview-site-operator", "organization-long", "organization-reader"} {
		t.Run(state, func(t *testing.T) {
			fixture := state
			organization := strings.HasPrefix(state, "organization-")
			state := strings.TrimPrefix(state, "organization-")
			info := &partials.CommonInfo{Principal: access.Principal{UserID: "owned-operator", Grants: []access.Grant{{Role: access.Operator, Scope: scope}}}, SM: &sessions.SessionManager{Manager: sm}, CSRFToken: "owned-csrf", TenantID: "1", SiteID: "1", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Owned organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
			if organization && state != "receipt-site-operator" && state != "preview-site-operator" && state != "reader" {
				info.Principal.Grants = []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}
			}
			if state == "reader" {
				info.Principal.Grants = []access.Grant{{Role: access.Viewer, Scope: scope}}
			}
			now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
			group := inventory.DeviceGroup{ID: "30000000-0000-0000-0000-000000000001", Scope: scope, Revision: 3, DeviceGroupDefinition: inventory.DeviceGroupDefinition{Name: "Owned <update group>", Rule: inventory.DeviceGroupRule{Search: "Owned"}}}
			if organization {
				group.Scope.SiteID = 0
			}
			plan := apple.UpdatePlan{ID: "70000000-0000-0000-0000-000000000001", Scope: apple.Scope{TenantID: 1, SiteID: 1}, Revision: 2, Actor: "owned-operator", CreatedAt: now, Definition: apple.UpdatePlanDefinition{Name: "Owned <update pilot>", Description: "Reviewed update", Platform: "ios", TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: "2026-10-01T18:00:00", DetailsURL: "https://example.test/update"}}
			target := apple.UpdatePlanGroupTarget{Selection: apple.UpdatePlanGroupSelection{DeviceID: "10000000-0000-0000-0000-000000000001", PolicyToken: strings.Repeat("a", 64)}, Entry: inventory.DeviceEntry{ID: "10000000-0000-0000-0000-000000000001", Name: "Owned iPhone", Platform: "iOS", OSVersion: "18.6"}}
			if state == "existing" {
				target.CurrentPolicy = &apple.UpdatePolicy{TargetVersion: "18.7", TargetBuild: "22H90", Deadline: "2026-11-01T18:00:00", DetailsURL: "https://example.test/previous"}
			}
			if state == "long" {
				group.Name = strings.Repeat("G", 110) + "<script>"
				plan.Definition.Name = strings.Repeat("P", 110) + "<script>"
				target.Entry.Name = strings.Repeat("N", 240) + "<script>"
			}
			preview := apple.UpdatePlanGroupPreview{Plan: plan, Group: group, Targets: []apple.UpdatePlanGroupTarget{target}, Excluded: []apple.ProfileGroupTarget{{Entry: inventory.DeviceEntry{ID: "owned-desktop", Name: "Owned Windows", Platform: "Windows"}, Reason: "not_apple_mdm"}}}
			if state == "excluded" {
				preview.Targets = nil
			}
			assignment := apple.UpdatePlanGroupAssignment{GroupScope: apple.Scope{TenantID: group.Scope.TenantID, SiteID: group.Scope.SiteID}, ID: "40000000-0000-0000-0000-000000000001", Scope: plan.Scope, RequestKey: "50000000-0000-0000-0000-000000000001", Plan: plan, Actor: "owned-operator", Group: apple.ProfileGroupSource{ID: group.ID, Revision: group.Revision, Name: group.Name, Rule: group.Rule}, CreatedAt: now, Commands: []apple.UpdatePlanGroupCommand{{Selection: target.Selection, CommandID: "60000000-0000-0000-0000-000000000001"}}}
			path := "/tenant/1/site/1/ios/update-plans/" + plan.ID + "/groups"
			c := echo.New().NewContext(httptest.NewRequest("GET", path, nil).WithContext(ctx), httptest.NewRecorder())
			var component templ.Component
			switch state {
			case "choose", "empty":
				archived := group
				archived.ID = "30000000-0000-0000-0000-000000000002"
				archived.Name = "Archived group"
				archived.Archived = true
				groups := []inventory.DeviceGroup{group, archived}
				if state == "empty" {
					groups = nil
				}
				component = AppleUpdatePlanGroups(c, info, plan, &inventory.DeviceGroupPage{Groups: groups}, DevicePagination{Next: UpdatePlanGroupSourceChoiceURL(info, plan, group.ID, organization)}, organization)
			case "assignment", "receipt-site-operator":
				component = AppleUpdatePlanGroupAssignment(c, info, assignment)
			case "history", "empty-history":
				items := []apple.UpdatePlanGroupAssignment{assignment}
				next := assignment.ID
				if state == "empty-history" {
					items = nil
					next = ""
				}
				component = AppleUpdatePlanGroupAssignments(c, info, plan.ID, items, next)
			case "progress":
				component = AppleUpdateGroupProgress(c, info, apple.UpdateGroupProgress{Assignment: assignment, AssessedAt: now, Counts: apple.UpdateGroupProgressCounts{Total: 1, Unverified: 1, PolicyMatches: 1, DeadlineUnverified: 1}, Devices: []apple.UpdateGroupDeviceProgress{{DeviceID: target.Selection.DeviceID, Name: target.Entry.Name, Availability: "available", PolicyState: "matches", Result: "unverified", Reason: "no_report"}}})
			default:
				component = AppleUpdatePlanGroupPreview(c, info, preview, assignment.RequestKey)
			}
			var body bytes.Buffer
			require.NoError(t, component.Render(ctx, &body))
			html := body.String()
			require.False(t, strings.Contains(html, plan.Definition.Name), "plan name was not escaped")
			require.False(t, strings.Contains(html, group.Name), "group name was not escaped")
			require.NotContains(t, html, "@Timestamp")
			require.NotContains(t, html, "@CSRF")
			confirming := state == "preview" || state == "existing" || state == "long"
			require.Equal(t, confirming, strings.Contains(html, "data-update-group-confirm"))
			if organization {
				require.NotContains(t, html, "data-update-schedule-confirm")
				require.NotContains(t, html, `action="/tenant/1/site/1/ios/update-plans/`+plan.ID+`/schedules"`)
				if state == "choose" {
					require.Contains(t, html, "source=organization")
				}
				if state != "empty" && state != "choose" && state != "history" {
					require.Contains(t, html, "Only the selected target site's members")
					require.NotContains(t, html, `href="/tenant/1/site/1/device-groups/`+group.ID+`"`)
					require.Equal(t, state != "receipt-site-operator" && state != "preview-site-operator" && state != "reader", strings.Contains(html, `href="/tenant/1/device-groups/`+group.ID+`"`))
				}
			}
			if confirming {
				require.Contains(t, html, `name="expected_revision" value="2"`)
				require.Contains(t, html, `name="group_revision" value="3"`)
				require.Contains(t, html, `name="csrf" value="owned-csrf"`)
				require.Contains(t, html, `name="group_source" value="`+profileGroupSourceKind(assignment.GroupScope)+`"`)
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "apple-update-group-"+fixture+".html"), body.Bytes(), 0644))
			}
		})
	}
}
