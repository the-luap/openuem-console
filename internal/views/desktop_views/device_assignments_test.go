package desktop_views

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
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestDeviceAssignmentViewsRequireExplicitDestinationAndConfirmation(t *testing.T) {
	require.NoError(t, locales.Load())
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "assignment-admin")
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "1", IsComputer: true, CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Example organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}, Principal: access.Principal{UserID: "assignment-admin", Grants: []access.Grant{{Role: access.Administrator}}}}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/computers/assignment-device/assignment", nil).WithContext(ctx), httptest.NewRecorder())
	for _, state := range []string{"choices", "choices-long", "individual", "review-site", "review-organization", "completed", "expired", "conflict"} {
		source := inventory.AssignmentLocation{TenantID: 1, SiteID: 1, Organization: "Example organization", Site: "Berlin"}
		target := inventory.AssignmentLocation{TenantID: 2, SiteID: 3, Organization: "Destination organization", Site: `West <script>window.assignmentOwned=true</script>`}
		if state == "choices-long" {
			target.Organization = strings.Repeat("Organization", 30)
			target.Site += strings.Repeat("LongSite", 40)
		}
		page := &inventory.DeviceAssignmentChoices{DeviceID: "assignment-device", DeviceName: "Finance laptop", Source: source, Locations: []inventory.AssignmentLocation{{TenantID: 1, SiteID: 2, Organization: "Example organization", Site: "Hamburg"}, target}, Next: 3}
		r := &inventory.DeviceAssignmentReview{ID: "a938f203-9961-4f40-8896-2e69d3f1225e", DeviceID: page.DeviceID, DeviceName: page.DeviceName, Actor: "assignment-admin", Source: source, Target: target, TagCount: 2, MetadataCount: 3, CreatedAt: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2100, 1, 1, 0, 10, 0, 0, time.UTC)}
		if state == "individual" {
			page.IndividualIdentity = true
			page.Locations = nil
			page.Next = 0
		}
		if state == "review-site" {
			r.Target = page.Locations[0]
		}
		if state == "completed" {
			completed := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
			r.CreatedAt = completed.Add(-time.Minute)
			r.ExpiresAt = completed.Add(9 * time.Minute)
			r.CompletedAt = &completed
		}
		if state == "expired" {
			r.CreatedAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
			r.ExpiresAt = r.CreatedAt.Add(10 * time.Minute)
		}
		var body bytes.Buffer
		switch state {
		case "choices", "choices-long", "individual":
			err = AssignmentChoices(c, info, page, "%_&", 0).Render(ctx, &body)
		case "conflict":
			err = AssignmentConflict(c, info, page.DeviceID, "The reviewed data changed. Nothing was moved by this request. Open a new review.").Render(ctx, &body)
		default:
			err = AssignmentReview(c, info, r).Render(ctx, &body)
		}
		require.NoError(t, err)
		html := body.String()
		require.NotContains(t, html, "<script>window.assignmentOwned")
		if state == "review-site" || state == "review-organization" {
			require.Contains(t, html, `name="confirm"`)
			require.Contains(t, html, `hx-boost="false"`)
			require.Contains(t, html, `name="csrf"`)
		}
		if state == "individual" || state == "completed" || state == "expired" || state == "conflict" {
			require.NotContains(t, html, `method="post"`)
		}
		if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
			require.NoError(t, os.MkdirAll(dir, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "device-assignment-"+state+".html"), body.Bytes(), 0600))
		}
	}
}
