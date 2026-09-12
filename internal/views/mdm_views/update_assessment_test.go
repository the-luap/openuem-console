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

func TestAppleDeviceUpdateAssessmentPages(t *testing.T) {
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "owned-operator")
	for _, state := range []string{"required", "compliant", "missing-build", "stale", "unmanaged", "error", "error-limited", "no-policy", "viewer", "long", "missing", "deadline-pending", "deadline-elapsed", "deadline-stale", "deadline-future", "deadline-invalid", "deadline-gap", "deadline-fold"} {
		t.Run(state, func(t *testing.T) {
			info := &partials.CommonInfo{Principal: access.Principal{UserID: "owned-operator", Grants: []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}}, SM: &sessions.SessionManager{Manager: sm}, CSRFToken: "owned-csrf", TenantID: "1", SiteID: "1", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Owned organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
			now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
			if state == "deadline-fold" {
				now = time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
			}
			d := &apple.Device{ID: "10000000-0000-0000-0000-000000000001", Name: "Owned update phone", Model: "iPhone16,1", OSVersion: "18.5", BuildVersion: "22F999", Status: "enrolled", Supervised: true, CertificateExpiresAt: now.AddDate(1, 0, 0), InventoryAt: &now}
			policy := &apple.UpdatePolicy{TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: "2026-10-01T18:00:00", Status: "waiting"}
			a := &apple.UpdateAssessment{PolicyToken: strings.Repeat("a", 64), DeviceID: d.ID, Availability: "available", Observation: &apple.OSObservation{Version: "18.7.1", Build: "22H100", Source: "declarative_status", RecordedAt: now.Add(-time.Hour)}, Policy: policy, Compliance: "compliant", AssessedAt: now}
			a.Deadline, _ = ownedDeadlineViewFixture(state, now)
			if _, local := ownedDeadlineViewFixture(state, now); local != "" {
				policy.Deadline = local
			}
			switch state {
			case "required":
				a.Compliance, a.Observation.Version, a.Observation.Build = "update_required", "18.6.2", "22G100"
			case "missing-build":
				a.Compliance, a.Reason, a.Observation.Build = "unknown", "missing_build", ""
			case "stale":
				a.Compliance, a.Reason, a.Observation.RecordedAt = "unknown", "stale_report", now.Add(-25*time.Hour)
			case "unmanaged":
				d.Status, a.Availability, a.Compliance, a.Reason = "revoked", "not_managed", "not_managed", "device_unavailable"
			case "error":
				policy.Status, policy.Error, a.PolicyHasError = "failed", "Owned <script>policy failure</script>", true
			case "error-limited":
				policy.Status, a.PolicyHasError, a.PolicyErrorTruncated = "failed", true, true
			case "no-policy":
				a.Policy, a.Compliance, a.Deadline = nil, "", nil
			case "viewer":
				info.Principal.Grants[0].Role = access.Viewer
			case "long":
				policy.Error = strings.Repeat("E", 8192)
				a.PolicyHasError = true
			case "missing":
				a.Observation, a.Compliance, a.Reason = nil, "unknown", "no_report"
			}
			detail := Detail{Device: d, UpdateAssessment: a, Policy: a.Policy, Compliance: a.Compliance, CatalogAt: &now, Releases: []apple.OSRelease{{Version: "18.7.1", Build: "22H100"}}}
			c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/ios/"+d.ID, nil).WithContext(ctx), httptest.NewRecorder())
			var body bytes.Buffer
			require.NoError(t, DeviceDetails(c, info, detail).Render(ctx, &body))
			html := body.String()
			require.Contains(t, html, "data-device-update-assessment")
			require.NotContains(t, html, "<script>policy failure</script>")
			require.NotContains(t, html, "@deviceUpdate")
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "apple-device-update-"+state+".html"), body.Bytes(), 0644))
			}
		})
	}
}
