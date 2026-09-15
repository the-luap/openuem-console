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
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestAppleUpdateGroupRemovalPages(t *testing.T) {
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "owned-operator")
	for _, state := range []string{"preview", "empty", "different", "mixed", "unavailable", "no-notification", "receipt", "receipt-no-notification", "history", "empty-history", "long"} {
		t.Run(state, func(t *testing.T) {
			info := &partials.CommonInfo{Principal: access.Principal{UserID: "owned-operator", Grants: []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}}, SM: &sessions.SessionManager{Manager: sm}, CSRFToken: "owned-csrf", TenantID: "1", SiteID: "1", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Owned organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
			now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
			plan := apple.UpdatePlan{ID: "70000000-0000-0000-0000-000000000001", Scope: apple.Scope{TenantID: 1, SiteID: 1}, Revision: 2, Actor: "owned-operator", CreatedAt: now.Add(-3 * time.Hour), Definition: apple.UpdatePlanDefinition{Name: "Owned <removal plan>", Platform: "ios", TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: "2026-10-01T18:00:00"}}
			original := apple.UpdatePlanGroupAssignment{ID: "40000000-0000-0000-0000-000000000001", Scope: plan.Scope, Plan: plan, Actor: "owned-operator", CreatedAt: now.Add(-time.Hour)}
			policy := plan.Definition.Policy()
			d := apple.UpdateGroupRemovalTarget{Selection: apple.UpdatePlanGroupSelection{DeviceID: "10000000-0000-0000-0000-000000000001", PolicyToken: strings.Repeat("b", 64)}, Name: "Owned <removal phone>", CurrentPolicy: &policy, NotificationAvailable: true}
			p := apple.UpdateGroupRemovalPreview{Assignment: original, AssessedAt: now, Devices: []apple.UpdateGroupRemovalTarget{d}}
			r := apple.UpdateGroupRemoval{ID: "60000000-0000-0000-0000-000000000001", Scope: plan.Scope, RequestKey: "50000000-0000-0000-0000-000000000001", Assignment: original, Actor: "owned-operator", CreatedAt: now, Commands: []apple.UpdatePlanGroupCommand{{Selection: d.Selection, CommandID: "80000000-0000-0000-0000-000000000001"}}}
			switch state {
			case "empty":
				p.Devices[0].Reason, p.Devices[0].CurrentPolicy = "absent", nil
			case "different":
				p.Devices[0].Reason, policy.Deadline = "different", "2026-11-01T18:00:00"
			case "mixed":
				second := d
				second.Selection.DeviceID, second.Reason, second.CurrentPolicy = "10000000-0000-0000-0000-000000000002", "absent", nil
				p.Devices = append(p.Devices, second)
			case "unavailable":
				p.Devices[0].Reason, p.Devices[0].Name, p.Devices[0].CurrentPolicy = "unavailable", "", nil
			case "no-notification":
				p.Devices[0].NotificationAvailable = false
			case "receipt-no-notification":
				r.Commands[0].CommandID = ""
			case "long":
				p.Devices[0].Name = strings.Repeat("N", 500) + "<script>"
				p.Assignment.Plan.Definition.Name = strings.Repeat("P", 100) + "<script>"
				policy.DetailsURL = "https://example.test/" + strings.Repeat("x", 1800)
			}
			c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1"+UpdateGroupRemovalPreviewPath(plan.ID, original.ID), nil).WithContext(ctx), httptest.NewRecorder())
			var page templ.Component = AppleUpdateGroupRemovalPreview(c, info, p, r.RequestKey)
			switch state {
			case "receipt", "receipt-no-notification":
				page = AppleUpdateGroupRemoval(c, info, r)
			case "history":
				page = AppleUpdateGroupRemovals(c, info, plan.ID, original.ID, []apple.UpdateGroupRemoval{r}, r.ID)
			case "empty-history":
				page = AppleUpdateGroupRemovals(c, info, plan.ID, original.ID, nil, "")
			}
			var body bytes.Buffer
			require.NoError(t, page.Render(ctx, &body))
			html := body.String()
			require.Contains(t, html, "data-update-group-removal")
			require.NotContains(t, html, "Owned <removal")
			require.NotContains(t, html, "@Timestamp")
			require.NotContains(t, html, "@appleUpdate")
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "apple-update-removal-"+state+".html"), body.Bytes(), 0644))
			}
		})
	}
}
