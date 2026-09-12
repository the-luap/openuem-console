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

func TestAppleUpdatePromotionPages(t *testing.T) {
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "owned-operator")
	scope := access.Scope{TenantID: 1, SiteID: 1}
	for _, state := range []string{"plans", "empty-plans", "groups", "empty-groups", "ready", "overlap", "unknown", "stale", "error", "exception", "post-exception", "different-policy", "unavailable", "incompatible", "pilot-only", "viewer", "receipt", "history", "empty-history", "long"} {
		t.Run(state, func(t *testing.T) {
			info := &partials.CommonInfo{Principal: access.Principal{UserID: "owned-operator", Grants: []access.Grant{{Role: access.Operator, Scope: scope}}}, SM: &sessions.SessionManager{Manager: sm}, CSRFToken: "owned-csrf", TenantID: "1", SiteID: "1", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Owned organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
			now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
			observed := now.Add(-time.Minute)
			plan := apple.UpdatePlan{ID: "30000000-0000-4000-8000-000000000001", Scope: apple.Scope{TenantID: 1, SiteID: 1}, Revision: 2, Definition: apple.UpdatePlanDefinition{Name: "Owned <pilot plan>", Platform: "ios", TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: "2026-10-01T18:00:00"}}
			policy := plan.Definition.Policy()
			pilotID := "10000000-0000-4000-8000-000000000001"
			newID := "10000000-0000-4000-8000-000000000002"
			pilotSelection := apple.UpdatePlanGroupSelection{DeviceID: pilotID, PolicyToken: strings.Repeat("a", 64)}
			original := apple.UpdatePlanGroupAssignment{ID: "40000000-0000-4000-8000-000000000001", Plan: plan, Scope: plan.Scope, CreatedAt: now.Add(-time.Hour), Commands: []apple.UpdatePlanGroupCommand{{Selection: pilotSelection, CommandID: "80000000-0000-4000-8000-000000000001"}}}
			d := apple.UpdateGroupDeviceProgress{DeviceID: pilotID, Name: "Owned <pilot phone>", Availability: "available", PolicyState: "matches", CurrentPolicy: &policy, RecordedAt: &observed, ReportSource: "declarative_status", ReportedVersion: "18.7.1", ReportedBuild: "22H100", Result: "target_reported"}
			readiness := apple.UpdatePilotDeviceReadiness{DeviceID: pilotID, Ready: true}
			destination := plan
			destination.ID = "30000000-0000-4000-8000-000000000002"
			destination.Definition.Name = "Owned <broad plan>"
			destination.Definition.Deadline = "2026-11-01T18:00:00"
			group := inventory.DeviceGroup{ID: "20000000-0000-4000-8000-000000000001", Scope: scope, Revision: 3, DeviceGroupDefinition: inventory.DeviceGroupDefinition{Name: "Owned <broad group>", Rule: inventory.DeviceGroupRule{Search: "Owned"}}}
			target := apple.UpdatePlanGroupTarget{Selection: apple.UpdatePlanGroupSelection{DeviceID: newID, PolicyToken: "none"}, Entry: inventory.DeviceEntry{ID: newID, Name: "Owned <destination phone>", Platform: "iOS", OSVersion: "18.6.2"}}
			p := apple.UpdatePromotionPreview{Destination: apple.UpdatePlanGroupPreview{Plan: destination, Group: group, Targets: []apple.UpdatePlanGroupTarget{target}, Excluded: []apple.ProfileGroupTarget{{Entry: inventory.DeviceEntry{ID: "owned-desktop", Name: "Owned <desktop>", Platform: "Windows"}, Reason: "not_apple_mdm"}}}, CompatibleTarget: true, NewTargets: 1, Ready: true}
			switch state {
			case "unknown":
				readiness.Ready = false
				readiness.Reason = "os_unverified"
				d.RecordedAt = nil
				d.Result = "unverified"
				d.Reason = "no_report"
			case "stale":
				original.CreatedAt = now.Add(-26 * time.Hour)
				readiness.Ready = false
				readiness.Reason = "os_unverified"
				observed = now.Add(-25 * time.Hour)
				d.Result = "unverified"
				d.Reason = "stale_report"
			case "error":
				readiness.Ready = false
				readiness.Reason = "policy_error"
				d.PolicyHasError = true
			case "exception":
				readiness.Ready = false
				readiness.Reason = "exception_active"
				d.ExceptionActive = true
				expires := now.Add(time.Hour)
				d.Exception = &apple.UpdateException{Kind: "pause", Reason: "Owned maintenance", CreatedAt: now.Add(-time.Minute), ExpiresAt: &expires}
			case "post-exception":
				readiness.Ready = false
				readiness.Reason = "awaiting_post_exception_report"
				d.Exception = &apple.UpdateException{Kind: "resume", CreatedAt: now.Add(-30 * time.Second), Reason: "Owned resumed maintenance"}
			case "different-policy":
				readiness.Ready = false
				readiness.Reason = "policy_different"
				d.PolicyState = "different"
			case "unavailable":
				readiness.Ready = false
				readiness.Reason = "device_unavailable"
				d.Availability = "unavailable"
				d.Name = ""
				d.RecordedAt = nil
			case "incompatible":
				p.CompatibleTarget = false
				p.Ready = false
				p.Destination.Plan.Definition.TargetBuild = "22H101"
			case "pilot-only":
				p.NewTargets = 0
				p.Ready = false
				p.Destination.Targets = nil
			case "viewer":
				info.Principal.Grants[0].Role = access.Viewer
			case "long":
				d.Name = strings.Repeat("N", 240) + "<script>"
				original.Plan.Definition.Name = strings.Repeat("P", 110) + "<script>"
				p.Destination.Plan.Definition.Name = strings.Repeat("D", 110) + "<script>"
				p.Destination.Group.Name = strings.Repeat("G", 110) + "<script>"
				p.Destination.Targets[0].Entry.Name = strings.Repeat("T", 240) + "<script>"
			}
			if state == "overlap" || state == "pilot-only" || state == "long" {
				p.PilotOverlap = []string{pilotID}
				p.Destination.Targets = append(p.Destination.Targets, apple.UpdatePlanGroupTarget{Selection: pilotSelection, Entry: inventory.DeviceEntry{ID: pilotID, Name: d.Name, Platform: "iOS", OSVersion: d.ReportedVersion}, CurrentPolicy: &policy})
			}
			p.Pilot = apple.UpdatePilotReadiness{Progress: apple.UpdateGroupProgress{Assignment: original, AssessedAt: now, Devices: []apple.UpdateGroupDeviceProgress{d}}, Devices: []apple.UpdatePilotDeviceReadiness{readiness}, AllReady: readiness.Ready}
			if readiness.Ready {
				p.Pilot.Ready = 1
			} else {
				p.Pilot.Blocked = 1
				p.Ready = false
			}
			child := apple.UpdatePlanGroupAssignment{ID: "40000000-0000-4000-8000-000000000002", Plan: destination, Scope: plan.Scope, CreatedAt: now, Group: apple.ProfileGroupSource{ID: group.ID, Revision: group.Revision, Name: group.Name, Rule: group.Rule}, Commands: []apple.UpdatePlanGroupCommand{{Selection: target.Selection, CommandID: "80000000-0000-4000-8000-000000000002"}}}
			ended := now.Add(-2 * time.Minute)
			r := apple.UpdatePromotion{ID: "50000000-0000-4000-8000-000000000001", RequestKey: "60000000-0000-4000-8000-000000000001", Scope: plan.Scope, PilotPlanID: plan.ID, PilotAssignmentID: original.ID, DestinationPlanID: destination.ID, AssignmentID: child.ID, Actor: "Owned <operator>", CreatedAt: now, DestinationRevision: 2, GroupRevision: 3, Pilot: &original, Assignment: &child, Evidence: &apple.UpdatePilotEvidence{AssessedAt: now, Devices: []apple.UpdatePilotDeviceEvidence{{DeviceID: pilotID, Observation: apple.OSObservation{Version: d.ReportedVersion, Build: d.ReportedBuild, Source: d.ReportSource, RecordedAt: observed}, IdentityExpiresAt: now.Add(365 * 24 * time.Hour), PolicyToken: pilotSelection.PolicyToken, ExceptionEndedAt: &ended}}}}
			c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1"+UpdatePromotionPath(plan.ID, original.ID), nil).WithContext(ctx), httptest.NewRecorder())
			var component templ.Component
			switch state {
			case "plans", "empty-plans":
				archived := destination
				archived.ID = "30000000-0000-4000-8000-000000000003"
				archived.Definition.Archived = true
				different := destination
				different.ID = "30000000-0000-4000-8000-000000000004"
				different.Definition.TargetBuild = "22H101"
				plans := []apple.UpdatePlan{destination, archived, different}
				if state == "empty-plans" {
					plans = nil
				}
				component = AppleUpdatePromotionPlans(c, info, p.Pilot, plans, DevicePagination{Next: "/tenant/1/site/1" + UpdatePromotionPath(plan.ID, original.ID) + "?after=" + different.ID})
			case "groups", "empty-groups":
				archived := group
				archived.ID = "20000000-0000-4000-8000-000000000002"
				archived.Archived = true
				groups := []inventory.DeviceGroup{group, archived}
				if state == "empty-groups" {
					groups = nil
				}
				component = AppleUpdatePromotionGroups(c, info, p.Pilot, destination, &inventory.DeviceGroupPage{Groups: groups}, DevicePagination{Next: UpdatePromotionGroupChoiceURL(info, original, destination, archived.ID)})
			case "receipt":
				component = AppleUpdatePromotion(c, info, r)
			case "history", "empty-history":
				items := []apple.UpdatePromotion{r}
				next := r.ID
				if state == "empty-history" {
					items = nil
					next = ""
				}
				component = AppleUpdatePromotions(c, info, plan.ID, original.ID, items, next)
			default:
				component = AppleUpdatePromotionPreview(c, info, p, r.RequestKey)
			}
			var body bytes.Buffer
			require.NoError(t, component.Render(ctx, &body))
			html := body.String()
			confirming := state == "ready" || state == "overlap" || state == "long"
			require.Equal(t, confirming, strings.Contains(html, "data-promotion-confirm"))
			pageHTML := html[strings.Index(html, "data-update-promotion-page"):]
			pageHTML = pageHTML[:strings.Index(pageHTML, "</main>")]
			require.False(t, strings.Contains(pageHTML, "<script>"), "source markup became executable inside the promotion page")
			require.NotContains(t, html, "@CSRF")
			require.NotContains(t, html, "@appleUpdate")
			if confirming {
				require.Contains(t, html, `name="expected_revision" value="2"`)
				require.Contains(t, html, `name="group_revision" value="3"`)
				require.Contains(t, html, `name="csrf" value="owned-csrf"`)
			}
			if state == "receipt" {
				require.Contains(t, html, "Saved original pilot evidence")
				require.Contains(t, html, "Latest exception ended")
				require.NotContains(t, html, pilotSelection.PolicyToken)
				require.NotContains(t, html, r.Actor)
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "apple-update-promotion-"+state+".html"), body.Bytes(), 0644))
			}
		})
	}
}
