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
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestAppleUpdateEscalationPages(t *testing.T) {
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "owned-operator")
	for _, state := range []string{"new", "watching", "attention", "awaiting", "acknowledged", "paused", "blocked-authority", "blocked-source", "viewer", "history", "event-configured", "event-acknowledged", "event-cleared", "event-attention", "event-blocked", "list", "empty", "long"} {
		t.Run(state, func(t *testing.T) {
			info := &partials.CommonInfo{Principal: access.Principal{UserID: "owned-operator", Grants: []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}}, SM: &sessions.SessionManager{Manager: sm}, CSRFToken: "owned-csrf", TenantID: "1", SiteID: "1", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Owned organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
			now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
			deadline := now.Add(-time.Hour)
			next := now.Add(5 * time.Minute)
			deviceID := "10000000-0000-4000-8000-000000000001"
			original := &apple.UpdatePlanGroupAssignment{ID: "40000000-0000-4000-8000-000000000001", CreatedAt: now.Add(-2 * time.Hour), Plan: apple.UpdatePlan{ID: "30000000-0000-4000-8000-000000000001", Revision: 1, Definition: apple.UpdatePlanDefinition{Name: "Owned <update monitor>", Platform: "ios", TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: "2026-09-12T11:00:00"}}}
			snapshot := &apple.UpdateEscalationSnapshot{AssessedAt: now, Devices: []apple.UpdateEscalationEvidence{{Decision: apple.UpdateEscalationDecision{DeviceID: deviceID, State: "attention", Reason: "update_required_after_deadline"}, Observation: &apple.OSObservation{Version: "18.6.2", Build: "22G100", Source: "device_information", RecordedAt: now}, Deadline: &apple.UpdateDeadlineAssessment{State: "elapsed", TimeZone: &apple.TimeZoneObservation{Name: "UTC", Source: "device_information", RecordedAt: now}, Earliest: &deadline, Latest: &deadline}}}}
			r := apple.UpdateEscalation{ID: "20000000-0000-4000-8000-000000000001", Scope: apple.Scope{TenantID: 1, SiteID: 1}, PlanID: original.Plan.ID, AssignmentID: original.ID, ConfigurationRevision: 1, Actor: "Owned <operator>", Enabled: true, Phase: "watching", CreatedAt: now.Add(-time.Hour), ConfiguredAt: now.Add(-time.Hour), UpdatedAt: now, CheckedAt: &now, NextCheckAt: &next, IncidentID: "60000000-0000-4000-8000-000000000001", OpenCount: 1, OpenTargets: []string{deviceID}, Snapshot: snapshot, Assignment: original}
			p := apple.UpdateGroupEscalationReview{Current: &r, Progress: apple.UpdateGroupProgress{Assignment: *original, AssessedAt: now}, Decisions: []apple.UpdateEscalationDecision{snapshot.Devices[0].Decision}, NeedsAttention: 1}
			e := apple.UpdateEscalationEvent{ID: "50000000-0000-4000-8000-000000000001", WatchID: r.ID, Scope: r.Scope, PlanID: r.PlanID, AssignmentID: r.AssignmentID, ConfigurationRevision: 1, Revision: 3, Kind: "acknowledged", Actor: r.Actor, CreatedAt: now, Enabled: true, Phase: "watching", IncidentID: r.IncidentID, OpenTargets: r.OpenTargets, Snapshot: snapshot, Assignment: original, Reason: "Owned <script>incident note</script>"}
			switch state {
			case "new":
				p.Current = nil
			case "watching":
				r.Snapshot = nil
				r.CheckedAt = nil
				r.OpenCount = 0
				r.OpenTargets = nil
				r.IncidentID = ""
			case "awaiting":
				r.AwaitingCount = 1
				r.AwaitingTargets = r.OpenTargets
				snapshot.Devices[0].Decision.State = "unverified"
				snapshot.Devices[0].Decision.Reason = "deadline_unverified"
				snapshot.Devices[0].Deadline = &apple.UpdateDeadlineAssessment{State: "unverified", Reason: "no_timezone"}
			case "acknowledged":
				r.AcknowledgmentID = e.ID
			case "paused":
				r.Enabled = false
				r.Phase = "paused"
				r.NextCheckAt = nil
			case "blocked-authority", "event-blocked":
				r.Phase = "blocked"
				r.Reason = "authority_changed"
				r.NextCheckAt = nil
				e.Kind = "blocked"
				e.Phase = r.Phase
				e.StateReason = r.Reason
				e.Reason = ""
			case "blocked-source":
				p.PreviewUnavailable = true
				r.Phase = "blocked"
				r.Reason = "source_unavailable"
				r.NextCheckAt = nil
			case "viewer":
				info.Principal.Grants[0].Role = access.Viewer
			case "event-configured":
				e.Kind = "configured"
				e.Reason = ""
				e.Snapshot = nil
				e.IncidentID = ""
				e.OpenTargets = nil
			case "event-attention":
				e.Kind = "attention"
				e.Reason = ""
			case "event-cleared":
				e.Kind = "cleared"
				e.Reason = ""
				e.IncidentID = ""
				e.OpenTargets = nil
				snapshot.Devices[0].Decision.State = "suppressed"
				snapshot.Devices[0].Decision.Reason = "exception_active"
			case "long":
				r.Actor = strings.Repeat("N", 250) + "<script>"
				original.Plan.Definition.Name = strings.Repeat("P", 250) + "<script>"
			}
			c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1"+UpdateEscalationPath(r.PlanID, r.AssignmentID), nil).WithContext(ctx), httptest.NewRecorder())
			var body bytes.Buffer
			switch {
			case state == "history":
				err = AppleUpdateEscalationEvents(c, info, r.PlanID, r.AssignmentID, []apple.UpdateEscalationEvent{e}, e.ID).Render(ctx, &body)
			case state == "list":
				err = AppleUpdateEscalations(c, info, []apple.UpdateEscalation{r}, r.ID).Render(ctx, &body)
			case state == "empty":
				err = AppleUpdateEscalations(c, info, nil, "").Render(ctx, &body)
			case strings.HasPrefix(state, "event-"):
				err = AppleUpdateEscalationEvent(c, info, e).Render(ctx, &body)
			default:
				err = AppleUpdateEscalationReview(c, info, p, "70000000-0000-4000-8000-000000000001", "70000000-0000-4000-8000-000000000002").Render(ctx, &body)
			}
			require.NoError(t, err)
			require.Contains(t, body.String(), "data-update-escalation-page")
			require.NotContains(t, body.String(), "<script>incident note</script>")
			require.NotContains(t, body.String(), original.Plan.Definition.Name)
			require.NotContains(t, body.String(), r.Actor)
			require.NotContains(t, body.String(), "@apple")
			if state == "viewer" {
				require.NotContains(t, body.String(), "data-escalation-action")
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "apple-update-escalation-"+state+".html"), body.Bytes(), 0644))
			}
		})
	}
}
