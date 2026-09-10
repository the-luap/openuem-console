package windows_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/invopop/ctxi18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func TestWindowsUnenrollmentViewsKeepRequestsReviewsAndReportsIndependent(t *testing.T) {
	if err := ctxi18n.LoadWithDefault(locales.Content, "en"); err != nil {
		t.Fatal(err)
	}
	ctx, err := ctxi18n.WithLocale(context.Background(), "en")
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	info := &partials.CommonInfo{Principal: access.Principal{UserID: "synthetic-admin", Grants: []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}}, SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "11", CSRFToken: "synthetic-csrf"}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/11/windows/test/disconnections/test", nil).WithContext(ctx), httptest.NewRecorder())
	now := time.Date(2026, 9, 10, 12, 13, 14, 123456000, time.UTC)
	for _, test := range []struct {
		phase              string
		reported, released bool
		role               access.Role
		cancel, review     bool
	}{
		{"queued", false, false, access.TenantAdmin, true, false}, {"blocked", false, false, access.TenantAdmin, true, false}, {"sent", false, false, access.TenantAdmin, false, true}, {"acknowledged", false, false, access.TenantAdmin, false, true}, {"unknown", false, false, access.TenantAdmin, false, true}, {"failed", false, false, access.TenantAdmin, false, true}, {"canceled", false, false, access.TenantAdmin, false, false}, {"expired", false, false, access.TenantAdmin, false, false},
		{"unknown", false, true, access.TenantAdmin, false, false}, {"acknowledged", true, false, access.TenantAdmin, false, false}, {"unknown", true, true, access.TenantAdmin, false, false}, {"sent", false, false, access.Viewer, false, false}, {"queued", false, false, access.Operator, false, false},
	} {
		t.Run(test.phase+"/"+string(test.role)+map[bool]string{true: "/reported"}[test.reported]+map[bool]string{true: "/reviewed"}[test.released], func(t *testing.T) {
			info.Principal.Grants[0].Role = test.role
			device := windows.DeviceMetadata{ID: "10000000-0000-4000-8000-000000000001", Name: "<script>device</script>", CertificateExpiresAt: time.Now().Add(time.Hour)}
			detail := windows.UnenrollmentRequestDetail{Command: windows.CSPCommand{ID: "20000000-0000-4000-8000-000000000001", DeviceID: device.ID, Phase: test.phase, Revision: 7, CreatedAt: now, ExpiresAt: now.Add(time.Hour), CreatedBy: "<script>creator</script>"}, Reason: "<script>intent</script>", ProviderID: "PRIVATE_PROVIDER_NOT_NEEDED_IN_UI"}
			if test.phase == "sent" || test.phase == "acknowledged" || test.phase == "unknown" || test.phase == "failed" {
				detail.Command.DeliveredAt = &now
				detail.Outcomes = []windows.CSPOperationOutcome{{Kind: "Exec", Status: 200, OriginalError: "<script>device error</script>"}}
			}
			if test.released {
				detail.Release = &windows.UnenrollmentRelease{ReleasedBy: "<script>reviewer</script>", ReviewedRevision: 6, ReleasedAt: now, Reason: "<script>review</script>"}
			}
			if test.reported {
				device.RevokedAt = &now
				device.Unenrollment = &windows.UnenrollmentReport{ID: "separate-report-id", ReceivedAt: now, FingerprintSHA256: strings.Repeat("ab", 32)}
			}
			var out bytes.Buffer
			if err := UnenrollmentRequest(c, info, device, detail).Render(ctx, &out); err != nil {
				t.Fatal(err)
			}
			html := out.String()
			for _, absent := range []string{"<script>device</script>", "<script>creator</script>", "<script>intent</script>", "<script>device error</script>", "<script>reviewer</script>", "<script>review</script>", detail.ProviderID} {
				if strings.Contains(html, absent) {
					t.Fatal("untrusted or unnecessary protected data escaped", absent)
				}
			}
			if strings.Contains(html, `name="confirm_cancel"`) != test.cancel || strings.Contains(html, `name="confirm_release"`) != test.review {
				t.Fatal("lifecycle action offered for wrong state or role")
			}
			if (test.cancel || test.review) && (!strings.Contains(html, `name="expected_revision" value="7"`) || !strings.Contains(html, `name="csrf" value="synthetic-csrf"`)) {
				t.Fatal("lifecycle form lost CSRF or reviewed revision")
			}
			for _, want := range []string{cspState(test.phase), "&lt;script&gt;intent&lt;/script&gt;", "&lt;script&gt;device&lt;/script&gt;", "2026-09-10 12:13:14.123456 UTC"} {
				if !strings.Contains(html, want) {
					t.Fatal("lifecycle detail lost meaning", want)
				}
			}
			if strings.Contains(html, "Review recorded") != test.released || strings.Contains(html, "Device disconnection reported") != test.reported {
				t.Fatal("request outcome invented separate evidence")
			}
			if test.reported && (!strings.Contains(html, "does not establish which request or person") || !strings.Contains(html, "has not been independently verified") || !strings.Contains(html, "separate-report-id")) {
				t.Fatal("report implied request attribution or cleanup")
			}
			if test.released && (!strings.Contains(html, "does not undo the delivered request") || !strings.Contains(html, "&lt;script&gt;review&lt;/script&gt;")) {
				t.Fatal("review lost reason or uncertainty")
			}
		})
	}
	info.Principal.Grants[0].Role = access.TenantAdmin
	device := windows.DeviceMetadata{ID: "10000000-0000-4000-8000-000000000001", Name: "<script>device</script>", CertificateExpiresAt: time.Now().Add(time.Hour)}
	draft := UnenrollmentDraft{Form: url.Values{"request_key": {"20000000-0000-4000-8000-000000000001"}, "hours": {"24"}, "reason": {"<script>intent</script>"}}}
	for _, preview := range []bool{false, true} {
		var out bytes.Buffer
		component := UnenrollmentForm(c, info, device, draft)
		if preview {
			component = UnenrollmentPreview(c, info, device, draft)
		}
		if err := component.Render(ctx, &out); err != nil {
			t.Fatal(err)
		}
		html := out.String()
		if strings.Contains(html, "<script>intent</script>") || !strings.Contains(html, "&lt;script&gt;intent&lt;/script&gt;") || !strings.Contains(html, `name="request_key" value="20000000-0000-4000-8000-000000000001"`) || strings.Contains(html, `name="confirm_disconnect"`) != preview {
			t.Fatal("draft lost escaping, request identity or preview boundary")
		}
		if preview && (!strings.Contains(html, "This preview has not queued a command") || !strings.Contains(html, "managed settings, certificates and data may be removed") || !strings.Contains(html, ">Edit request</button>")) {
			t.Fatal("preview lost consequences or edit path")
		}
	}
}
