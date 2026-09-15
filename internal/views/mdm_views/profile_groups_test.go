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

func TestAppleProfileGroupPages(t *testing.T) {
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "owned-operator")
	scope := access.Scope{TenantID: 1, SiteID: 1}
	for _, state := range []string{"choose", "empty", "preview", "remove", "excluded", "assignment", "history", "empty-history", "long", "organization-choose", "organization-empty", "organization-preview", "organization-remove", "organization-excluded", "organization-assignment", "organization-history", "organization-reader", "organization-receipt-site-operator", "organization-long"} {
		t.Run(state, func(t *testing.T) {
			organization := strings.HasPrefix(state, "organization-")
			mode := strings.TrimPrefix(state, "organization-")
			if mode == "reader" {
				mode = "preview"
			}
			if mode == "receipt-site-operator" {
				mode = "assignment"
			}

			info := &partials.CommonInfo{Principal: access.Principal{UserID: "owned-operator", Grants: []access.Grant{{Role: access.Operator, Scope: scope}}}, SM: &sessions.SessionManager{Manager: sm}, CSRFToken: "owned-csrf", TenantID: "1", SiteID: "1", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Owned organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
			now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
			group := inventory.DeviceGroup{ID: "30000000-0000-0000-0000-000000000001", Scope: scope, Revision: 3, DeviceGroupDefinition: inventory.DeviceGroupDefinition{Name: "Owned <Apple group>", Description: "Current group rule", Rule: inventory.DeviceGroupRule{Search: "Owned"}}, Actor: "owned-operator", CreatedAt: now}
			choice := ProfileGroupChoice{ProfileID: "20000000-0000-0000-0000-000000000001", ProfileName: "Owned <Wi-Fi>", Revision: 2, Desired: "installed"}
			if organization {
				choice.Organization = true
				group.Scope.SiteID = 0
				info.Principal.Grants = []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}
				if state == "organization-reader" {
					info.Principal.Grants[0].Role = access.Viewer
				}
				if state == "organization-receipt-site-operator" {
					info.Principal.Grants = []access.Grant{{Role: access.Operator, Scope: scope}}
				}
			}
			if mode == "remove" {
				choice.Desired = "removed"
			}
			if mode == "long" {
				group.Name = strings.Repeat("G", 110) + "<script>"
				group.Rule.Search = strings.Repeat("S", 120)
				choice.ProfileName = strings.Repeat("P", 200) + "<script>"
			}
			target := apple.ProfileGroupTarget{DeviceID: "10000000-0000-0000-0000-000000000001", Entry: inventory.DeviceEntry{ID: "10000000-0000-0000-0000-000000000001", Name: "Owned iPhone", Platform: "iOS", OSVersion: "18.6"}}
			if mode == "long" {
				target.Entry.Name = strings.Repeat("N", 220) + "<script>"
			}
			preview := apple.ProfileGroupPreview{Group: group, ProfileID: choice.ProfileID, ProfileName: choice.ProfileName, ProfileRevision: choice.Revision, Desired: choice.Desired, Targets: []apple.ProfileGroupTarget{target}, Excluded: []apple.ProfileGroupTarget{{Entry: inventory.DeviceEntry{ID: "owned-desktop", Name: "Owned Windows", Platform: "Windows"}, Reason: "not_apple_mdm"}}}
			if mode == "excluded" {
				preview.Targets = nil
			}
			assignment := apple.ProfileGroupAssignment{GroupScope: apple.Scope{TenantID: group.Scope.TenantID, SiteID: group.Scope.SiteID}, ID: "40000000-0000-0000-0000-000000000001", Scope: apple.Scope{TenantID: 1, SiteID: 1}, RequestKey: "50000000-0000-0000-0000-000000000001", ProfileID: choice.ProfileID, ProfileRevision: choice.Revision, ProfileName: choice.ProfileName, Actor: "owned-operator", Desired: choice.Desired, CreatedAt: now, Group: apple.ProfileGroupSource{ID: group.ID, Revision: group.Revision, Name: group.Name, Rule: group.Rule}, Commands: []apple.ProfileGroupCommand{{DeviceID: target.DeviceID, CommandID: "60000000-0000-0000-0000-000000000001"}}}
			c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/ios/configurations/"+choice.ProfileID+"/groups", nil).WithContext(ctx), httptest.NewRecorder())
			var component templ.Component
			switch mode {
			case "choose", "empty":
				archived := group
				archived.ID = "30000000-0000-0000-0000-000000000002"
				archived.Name = "Archived group"
				archived.Archived = true
				groups := []inventory.DeviceGroup{group, archived}
				if mode == "empty" {
					groups = nil
				}
				component = AppleProfileGroups(c, info, choice, &inventory.DeviceGroupPage{Groups: groups}, DevicePagination{Next: ProfileGroupChoiceURL(info, choice, group.ID)})
			case "assignment":
				component = AppleProfileGroupAssignment(c, info, assignment)
			case "history", "empty-history":
				items := []apple.ProfileGroupAssignment{assignment}
				next := assignment.ID
				if mode == "empty-history" {
					items = nil
					next = ""
				}
				component = AppleProfileGroupAssignments(c, info, choice.ProfileID, items, next)
			default:
				component = AppleProfileGroupPreview(c, info, preview, assignment.RequestKey)
			}
			var body bytes.Buffer
			require.NoError(t, component.Render(ctx, &body))
			html := body.String()
			require.False(t, strings.Contains(html, group.Name), "group name was not escaped")
			require.NotContains(t, html, "@Timestamp")
			require.NotContains(t, html, "@CSRF")
			require.NotContains(t, html, choice.ProfileName)
			if (mode == "preview" || mode == "remove" || mode == "long") && state != "organization-reader" {
				require.Contains(t, html, `name="group_source" value="`+profileGroupSourceKind(assignment.GroupScope)+`"`)
				require.Contains(t, html, `name="expected_revision" value="2"`)
				require.Contains(t, html, `name="group_revision" value="3"`)
				require.Contains(t, html, `name="desired" value="`+choice.Desired+`"`)
				require.Contains(t, html, `name="csrf" value="owned-csrf"`)
			} else {
				require.NotContains(t, html, "data-profile-group-confirm")
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "apple-profile-group-"+state+".html"), body.Bytes(), 0644))
			}
		})
	}
}
