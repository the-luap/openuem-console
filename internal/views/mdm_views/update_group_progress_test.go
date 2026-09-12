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

func TestAppleUpdateGroupProgressPages(t *testing.T) {
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "owned-operator")
	scope := access.Scope{TenantID: 1, SiteID: 1}
	for _, state := range []string{"reported", "required", "unverified", "different", "removed", "unavailable", "attention", "mixed", "long", "deadline-elapsed", "deadline-fold", "deadline-stale"} {
		t.Run(state, func(t *testing.T) {
			info := &partials.CommonInfo{Principal: access.Principal{UserID: "owned-operator", Grants: []access.Grant{{Role: access.Operator, Scope: scope}}}, SM: &sessions.SessionManager{Manager: sm}, CSRFToken: "owned-csrf", TenantID: "1", SiteID: "1", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Owned organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
			now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
			if state == "deadline-fold" {
				now = time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
			}
			observed := now.Add(-time.Minute)
			plan := apple.UpdatePlan{ID: "70000000-0000-0000-0000-000000000001", Scope: apple.Scope{TenantID: 1, SiteID: 1}, Revision: 2, Actor: "owned-operator", CreatedAt: now.Add(-3 * time.Hour), Definition: apple.UpdatePlanDefinition{Name: "Owned <progress pilot>", Platform: "ios", TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: "2026-10-01T18:00:00"}}
			policy := plan.Definition.Policy()
			policy.Status = "enforced"
			receipt := apple.UpdatePlanGroupAssignment{ID: "40000000-0000-0000-0000-000000000001", Plan: plan, Scope: plan.Scope, CreatedAt: now.Add(-time.Hour), Group: apple.ProfileGroupSource{ID: "30000000-0000-0000-0000-000000000001", Revision: 3, Name: "Owned <progress group>", Rule: inventory.DeviceGroupRule{Search: "Owned"}}}
			d := apple.UpdateGroupDeviceProgress{DeviceID: "10000000-0000-0000-0000-000000000001", Name: "Owned <progress phone>", Availability: "available", PolicyState: "matches", CurrentPolicy: &policy, NotificationStatus: "acknowledged", ReportedVersion: "18.7.1", ReportedBuild: "22H100", ReportSource: "declarative_status", RecordedAt: &observed, Result: "target_reported"}
			d.Deadline, _ = ownedDeadlineViewFixture(state, now)
			if _, local := ownedDeadlineViewFixture(state, now); local != "" {
				receipt.Plan.Definition.Deadline, policy.Deadline = local, local
			}
			switch state {
			case "required", "deadline-elapsed":
				d.Result = "update_required"
				d.ReportedVersion = "18.6.2"
				d.ReportedBuild = "22G100"
			case "unverified":
				d.Result = "unverified"
				d.Reason = "missing_build"
				d.ReportedBuild = ""
			case "different":
				d.PolicyState = "different"
				policy.Deadline = "2026-11-01T18:00:00"
			case "removed":
				d.PolicyState = "absent"
				d.CurrentPolicy = nil
			case "unavailable":
				d.Name = ""
				d.Availability = "unavailable"
				d.NotificationStatus = "unavailable"
				d.PolicyState = "unknown"
				d.CurrentPolicy = nil
				d.RecordedAt = nil
				d.ReportedVersion = ""
				d.ReportedBuild = ""
				d.Result = "unverified"
				d.Reason = "device_unavailable"
			case "attention":
				policy.Status = "failed"
				d.PolicyHasError = true
			case "long":
				d.Name = strings.Repeat("N", 240) + "<script>"
				receipt.Plan.Definition.Name = strings.Repeat("P", 110) + "<script>"
				receipt.Group.Name = strings.Repeat("G", 110) + "<script>"
			}
			p := apple.UpdateGroupProgress{Assignment: receipt, AssessedAt: now, Devices: []apple.UpdateGroupDeviceProgress{d}}
			if state == "mixed" {
				second := d
				second.DeviceID = "10000000-0000-0000-0000-000000000002"
				second.Name = "Owned missing-build phone"
				second.Result = "unverified"
				second.Reason = "missing_build"
				second.ReportedBuild = ""
				second.PolicyState = "absent"
				second.CurrentPolicy = nil
				p.Devices = append(p.Devices, second)
			}
			for _, device := range p.Devices {
				p.Counts.Total++
				switch device.Deadline.State {
				case "pending":
					p.Counts.DeadlinePending++
				case "elapsed":
					p.Counts.DeadlineElapsed++
					if device.Result == "update_required" {
						p.Counts.UpdateRequiredAfterDeadline++
					}
				default:
					p.Counts.DeadlineUnverified++
				}
				switch device.Result {
				case "target_reported":
					p.Counts.TargetReported++
				case "update_required":
					p.Counts.UpdateRequired++
				default:
					p.Counts.Unverified++
				}
				switch device.PolicyState {
				case "matches":
					p.Counts.PolicyMatches++
				case "different":
					p.Counts.PolicyDifferent++
				case "absent":
					p.Counts.PolicyAbsent++
				}
				if device.Availability != "available" {
					p.Counts.Unavailable++
				}
				if device.PolicyHasError && device.PolicyState == "matches" {
					p.Counts.PolicyAttention++
				}
			}
			c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1"+UpdateGroupProgressPath(receipt.Plan.ID, receipt.ID), nil).WithContext(ctx), httptest.NewRecorder())
			var body bytes.Buffer
			require.NoError(t, AppleUpdateGroupProgress(c, info, p).Render(ctx, &body))
			html := body.String()
			require.Contains(t, html, "data-update-group-progress")
			require.NotContains(t, html, receipt.Plan.Definition.Name)
			require.NotContains(t, html, receipt.Group.Name)
			if d.Name != "" {
				require.NotContains(t, html, d.Name)
			}
			require.NotContains(t, html, "@appleUpdate")
			require.NotContains(t, html, "data-update-group-confirm")
			require.NotContains(t, html, "data-update-schedule-confirm")
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "apple-update-progress-"+state+".html"), body.Bytes(), 0644))
			}
		})
	}
}
