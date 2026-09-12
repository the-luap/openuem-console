package windows_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"net/url"
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
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestWindowsGroupAssignmentViews(t *testing.T) {
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "owned-operator")
	scope := access.Scope{TenantID: 1, SiteID: 1}
	info := &partials.CommonInfo{Principal: access.Principal{UserID: "owned-operator", Grants: []access.Grant{{Role: access.Operator, Scope: scope}}}, SM: &sessions.SessionManager{Manager: sm}, CSRFToken: "owned-csrf", TenantID: "1", SiteID: "1", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Owned organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
	for _, state := range []string{"choose", "empty", "form", "preview", "history", "long", "schedule-choose", "schedule-form", "schedule-preview", "schedule-history", "schedule-group-changed", "schedule-sources-changed"} {
		t.Run(state, func(t *testing.T) {
			scheduled := strings.HasPrefix(state, "schedule-")
			baseState := strings.TrimPrefix(state, "schedule-")
			action := "assign"
			if scheduled {
				action = "schedule"
			}
			now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
			zero := 0
			ring := windows.UpdateRingRevision{RingID: "10000000-0000-4000-8000-000000000001", Scope: scope, Revision: 1, Name: "Owned update ring", Enabled: true, Policy: windows.UpdatePolicy{QualityDeferralDays: &zero}}
			group := inventory.DeviceGroup{ID: "20000000-0000-4000-8000-000000000001", Scope: scope, Revision: 3, DeviceGroupDefinition: inventory.DeviceGroupDefinition{Name: "Owned <Windows group>", Rule: inventory.DeviceGroupRule{Platform: "windows", Search: "Owned"}}}
			if state == "long" {
				group.Name = strings.Repeat("x", 110) + "<script>"
				group.Rule.Search = strings.Repeat("Q", 256)
			}
			preview := &windows.UpdateGroupPreview{Source: windows.UpdateGroupSource{ID: group.ID, Revision: 3, Name: group.Name, Rule: group.Rule}, Targets: []string{"30000000-0000-4000-8000-000000000001"}, Excluded: []inventory.DeviceEntry{{Kind: "desktop", ID: "owned-agent", Name: "Owned <excluded agent>"}}}
			draft := UpdateAssignmentDraft{Ring: ring, Group: preview, Form: url.Values{"ring_revision": {"1"}, "request_key": {"40000000-0000-4000-8000-000000000001"}, "mode": {"apply"}, "hours": {"24"}, "devices": {preview.Targets[0]}, "group_id": {group.ID}, "group_revision": {"3"}}, Devices: []windows.DeviceMetadata{{ID: preview.Targets[0], Name: "Owned native Windows", CertificateExpiresAt: now.Add(time.Hour)}}}
			draft.Scheduled = scheduled
			if scheduled {
				draft.NotBefore = now.Add(time.Hour)
				draft.ActivationWindow = time.Hour
				draft.Form.Set("not_before", "2026-09-12T13:00")
				draft.Form.Set("activation_minutes", "60")
			}
			c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/windows/update-rings/"+ring.RingID+"/assign", nil).WithContext(ctx), httptest.NewRecorder())
			var view templ.Component
			switch baseState {
			case "choose", "empty":
				archived := group
				archived.ID = "20000000-0000-4000-8000-000000000002"
				archived.Archived = true
				groups := []inventory.DeviceGroup{group, archived}
				if state == "empty" {
					groups = nil
				}
				view = UpdateAssignmentGroups(c, info, ring, "apply", &inventory.DeviceGroupPage{Groups: groups}, mdm_views.DevicePagination{Next: "/tenant/1/site/1/windows/update-rings/" + ring.RingID + "/" + action + "/groups?revision=1&mode=apply&after=" + group.ID}, scheduled)
			case "form":
				view = UpdateAssignmentForm(c, info, draft)
			case "preview", "long":
				view = UpdateAssignmentPreview(c, info, draft)
			case "history", "group-changed", "sources-changed":
				if scheduled {
					phase, reason := "scheduled", ""
					if baseState != "history" {
						phase = "blocked"
						reason = strings.ReplaceAll(baseState, "-", "_")
						if baseState == "sources-changed" {
							reason = "group_sources_changed"
						}
					}
					view = UpdateSchedule(c, info, windows.UpdateSchedule{ID: "60000000-0000-4000-8000-000000000001", Group: &preview.Source, Scope: scope, RingID: ring.RingID, RingRevision: 1, CreatedAt: now, UpdatedAt: now, NotBefore: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour), Lifetime: 24 * time.Hour, Phase: phase, Reason: reason, Revision: 1}, ring, nil)
				} else {
					view = UpdateRollout(c, info, windows.UpdateRollout{ID: "50000000-0000-4000-8000-000000000001", Group: &preview.Source, Scope: scope, RingID: ring.RingID, RingRevision: 1, CreatedAt: now, Lifetime: 24 * time.Hour}, nil)
				}
			}
			var body bytes.Buffer
			require.NoError(t, view.Render(ctx, &body))
			html := body.String()
			require.False(t, strings.Contains(html, group.Name), "group name was not escaped")
			require.False(t, strings.Contains(html, "<excluded agent>"), "exclusion name was not escaped")
			require.False(t, strings.Contains(html, "windows_groups."), "missing group locale key")
			if baseState == "form" || baseState == "preview" || baseState == "long" {
				require.Contains(t, html, `name="group_id" value="`+group.ID+`"`)
				require.Contains(t, html, `name="group_revision" value="3"`)
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "windows-group-"+state+".html"), body.Bytes(), 0644))
			}
		})
	}
}
