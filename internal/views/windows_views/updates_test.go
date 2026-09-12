package windows_views

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
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func TestUpdateViewsPreserveHistoricalEvidenceAndCancellationBoundary(t *testing.T) {
	if err := locales.Load(); err != nil {
		t.Fatal(err)
	}
	ctx, err := locales.WithLocale(context.Background(), "en")
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	info := &partials.CommonInfo{Principal: access.Principal{UserID: "synthetic-operator", Grants: []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 11}}}}, SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "11", CSRFToken: "synthetic-csrf"}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/11/windows/device/updates/run", nil).WithContext(ctx), httptest.NewRecorder())
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	zero, seven, disabled := 0, 7, false
	device := windows.DeviceMetadata{ID: "10000000-0000-4000-8000-000000000001", Name: "Synthetic Windows"}
	for _, test := range []struct {
		name, phase, mode, firstStep string
		cancel                       bool
		outcomes                     []windows.UpdateSettingOutcome
	}{
		{"pending", "verification_pending", "apply", "acknowledged", true, []windows.UpdateSettingOutcome{{Name: "DeferQualityUpdatesPeriodInDays", Expected: 0, Configured: &zero, Effective: &seven, ConfigStatus: 200, EffectiveStatus: 200, State: "effective_value_mismatch", EvidenceReceivedAt: &now}}},
		{"sent", "verification_pending", "apply", "sent", false, nil},
		{"uncertain", "unknown", "apply", "unknown", false, nil},
		{"verified", "verified", "apply", "acknowledged", false, []windows.UpdateSettingOutcome{{Name: "DeferQualityUpdatesPeriodInDays", Expected: 0, Configured: &zero, Effective: &zero, ConfigStatus: 200, EffectiveStatus: 200, State: "verified", EvidenceReceivedAt: &now}}},
		{"removed", "removed", "remove", "acknowledged", false, []windows.UpdateSettingOutcome{{Name: "DeferQualityUpdatesPeriodInDays", Expected: 0, Effective: &seven, ConfigStatus: 404, EffectiveStatus: 200, State: "removed", EvidenceReceivedAt: &now}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			detail := windows.UpdateRunDetail{Run: windows.UpdateRun{ID: "20000000-0000-4000-8000-000000000001", DeviceID: device.ID, Mode: test.mode, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, Name: "Policy <script>unsafe</script>", Policy: windows.UpdatePolicy{QualityDeferralDays: &zero, ExcludeDrivers: &disabled}, Phase: test.phase, Outcomes: test.outcomes, Platform: windows.UpdatePlatform{Version: "10.0.26100.1", SupportState: "unknown", ExtendedSecurityUpdates: "not_assessed"}, Steps: []windows.CSPCommand{{Phase: test.firstStep}, {Phase: "acknowledged"}, {Phase: "acknowledged"}}}
			if test.cancel || test.firstStep == "sent" || test.firstStep == "unknown" {
				detail.Steps[2].Phase = "blocked"
			}
			var out bytes.Buffer
			if err := UpdateRun(c, info, device, detail).Render(ctx, &out); err != nil {
				t.Fatal(err)
			}
			html := out.String()
			for _, want := range []string{"They do not prove patch download", "do not continuously check", "Unmanaged", "<dd>0</dd>", "<dd>No</dd>", "Servicing support</dt><dd>Not established", "not assessed"} {
				if !strings.Contains(html, want) {
					t.Fatal("update evidence lost its meaning", want)
				}
			}
			if strings.Contains(html, "<script>unsafe</script>") || strings.Contains(html, `name="confirm_cancel"`) != test.cancel {
				t.Fatal("unsafe update rendering or cancellation boundary")
			}
			if test.name == "pending" && (!strings.Contains(html, "Effective value differs") || !strings.Contains(html, "Waiting for policy read-back")) {
				t.Fatal("partial verification erased earlier drift")
			}
			if test.mode == "remove" && (!strings.Contains(html, "No readable value") || !strings.Contains(html, "Status 404") || !strings.Contains(html, "another source may remain")) {
				t.Fatal("removal confused absence with a numeric zero")
			}
			writeWindowsBrowserFixture(t, "windows-update-"+test.name, out.Bytes())
			if dir := os.Getenv("OPENUEM_WINDOWS_UI_ARTIFACTS"); dir != "" {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "windows-update-"+test.name+"-view.html"), out.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
