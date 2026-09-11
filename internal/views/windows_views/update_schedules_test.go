package windows_views

import (
	"bytes"
	"context"
	"net/http/httptest"
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

func TestWindowsScheduleViewsPreserveTimingTargetsAndCancellationBoundary(t *testing.T) {
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
	scope := access.Scope{TenantID: 1, SiteID: 11}
	info := &partials.CommonInfo{Principal: access.Principal{UserID: "synthetic-operator", Grants: []access.Grant{{Role: access.Operator, Scope: scope}}}, SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "11", CSRFToken: "synthetic-csrf"}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/11/windows/update-schedules/test", nil).WithContext(ctx), httptest.NewRecorder())
	start := time.Date(2026, 9, 10, 14, 15, 16, 123456000, time.FixedZone("UTC+2", 2*60*60))
	zero := 0
	ring := windows.UpdateRingRevision{RingID: "10000000-0000-4000-8000-000000000001", Revision: 7, Name: "Historical <script>ring</script>", Policy: windows.UpdatePolicy{QualityDeferralDays: &zero}}
	for _, test := range []struct {
		state, reason, label string
		cancel               bool
	}{
		{"scheduled", "", "Scheduled; not activated", true},
		{"waiting", "device_queue_full", "Waiting to retry activation", true},
		{"activated", "", "Activated; device runs created", false},
		{"blocked", "authority_changed", "Blocked; a new review is required", false},
		{"expired", "activation_window_expired", "Activation window expired", false},
		{"canceled", "canceled_by_operator", "Canceled before activation", false},
	} {
		t.Run(test.state, func(t *testing.T) {
			s := windows.UpdateSchedule{ID: "20000000-0000-4000-8000-000000000001", RingID: ring.RingID, RingRevision: 7, Scope: scope, Mode: "remove", Phase: test.state, Reason: test.reason, Revision: 3, NotBefore: start, ExpiresAt: start.Add(90 * time.Minute), CreatedAt: start.Add(-time.Hour), UpdatedAt: start, NextAttemptAt: start.Add(time.Minute), Lifetime: 90 * time.Minute}
			if test.state == "activated" {
				s.RolloutID = "30000000-0000-4000-8000-000000000001"
			}
			if !test.cancel {
				s.CompletedAt = &start
			}
			targets := []UpdateScheduleTarget{{ID: "40000000-0000-4000-8000-000000000001", Device: &windows.DeviceMetadata{Name: "Device <script>name</script>"}}, {ID: "50000000-0000-4000-8000-000000000001"}}
			var out bytes.Buffer
			if err := UpdateSchedule(c, info, s, ring, targets).Render(ctx, &out); err != nil {
				t.Fatal(err)
			}
			html := out.String()
			for _, want := range []string{test.label, "2026-09-10 12:15:16.123456 UTC", "2026-09-10 13:45:16.123456 UTC", "5400 seconds", "Unavailable in this site", "Original target retained", targets[1].ID, "<dd>0</dd>", "not an installation or restart maintenance window"} {
				if !strings.Contains(html, want) {
					t.Fatal("schedule meaning lost", want)
				}
			}
			if strings.Contains(html, "<script>ring</script>") || strings.Contains(html, "<script>name</script>") || strings.Contains(html, `name="confirm_cancel"`) != test.cancel {
				t.Fatal("unsafe schedule rendering or cancellation boundary")
			}
			if test.cancel && !strings.Contains(html, `name="expected_revision" value="3"`) {
				t.Fatal("cancel form lost reviewed state revision")
			}
			if strings.Contains(html, "Open activated device runs") != (test.state == "activated") {
				t.Fatal("unactivated schedule offered device-run evidence")
			}
		})
	}
}
