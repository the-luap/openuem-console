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
	"github.com/invopop/ctxi18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func TestWindowsCertificateHealthViewPreservesLifecycleAndScopedLinks(t *testing.T) {
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
	info := &partials.CommonInfo{Principal: access.Principal{UserID: "synthetic-admin", Grants: []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}}, SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "-1", CSRFToken: "synthetic-csrf"}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/windows/certificate-health", nil).WithContext(ctx), httptest.NewRecorder())
	now := time.Date(2026, 9, 10, 12, 13, 14, 123456000, time.UTC)
	device := windows.DeviceMetadata{ID: "10000000-0000-4000-8000-000000000001", Scope: access.Scope{TenantID: 1, SiteID: 11}, Name: "<script>Device</script> " + strings.Repeat("LongName", 20)}
	options := windows.CertificateHealthOptions{Search: "A&B", Filter: "pending", WithinDays: 45, Offset: 25, Limit: 26}
	for _, state := range []string{"valid", "renewal_due", "expires_soon", "expired", "retired", "empty"} {
		t.Run(state, func(t *testing.T) {
			report := windows.CertificateHealthReport{Scope: access.Scope{TenantID: 1}, AssessedAt: now, Authority: &windows.CertificateAuthorityHealth{ID: "synthetic-issuer", FingerprintSHA256: strings.Repeat("ab", 32), State: "issuance_ending", ExpiresAt: now.Add(365 * 24 * time.Hour), IssuanceEndsAt: now.Add(20 * 24 * time.Hour), ValiditySeconds: 90 * 86400, RenewalSeconds: 14 * 86400}}
			row := windows.DeviceCertificateHealth{Device: device, Current: windows.RenewalCertificateMetadata{ID: "current-certificate", FingerprintSHA256: strings.Repeat("cd", 32), ExpiresAt: now.Add(time.Hour)}, CurrentState: state, RenewalOpensAt: now.Add(-time.Hour)}
			if state == "expired" || state == "renewal_due" {
				row.Pending = &windows.CertificateRenewal{ID: "pending-renewal"}
				row.Replacement = &windows.RenewalCertificateMetadata{ID: "replacement-certificate", ExpiresAt: now.Add(90 * 24 * time.Hour)}
				row.ReplacementState = "valid"
			} else if state == "valid" {
				row.ConfirmedRenewalID = "confirmed-renewal"
			}
			if state == "retired" {
				row.Device.RevokedAt = &now
				row.Device.Unenrollment = &windows.UnenrollmentReport{ReceivedAt: now}
			}
			if state != "empty" {
				report.Devices = []windows.DeviceCertificateHealth{row}
			} else {
				report.Authority = nil
			}
			var out bytes.Buffer
			if err := CertificateHealth(c, info, report, options, true).Render(ctx, &out); err != nil {
				t.Fatal(err)
			}
			html := out.String()
			_, filters, found := strings.Cut(html, `name="filter">`)
			filters, _, _ = strings.Cut(filters, "</select>")
			if !found || strings.Count(filters, " selected") != 1 || !strings.Contains(filters, `<option value="pending" selected>`) {
				t.Fatal("health filter did not select exactly the requested option")
			}
			for _, want := range []string{"Windows certificate health", "2026-09-10 12:13:14.123456 UTC", "does not confirm that Windows has scheduled a renewal", `value="45"`, `value="A&amp;B"`, "days=45&amp;filter=pending&amp;offset=50&amp;q=A%26B"} {
				if !strings.Contains(html, want) {
					t.Fatal("health view missing", want)
				}
			}
			if state != "empty" {
				for _, want := range []string{certificateHealthLabel(state), "&lt;script&gt;Device&lt;/script&gt;", "/tenant/1/site/11/windows/" + device.ID + "/renewals", "Full-lifetime issuance ends", row.Current.FingerprintSHA256} {
					if !strings.Contains(html, want) {
						t.Fatal("lifecycle or concrete scope link missing", want)
					}
				}
			}
			if strings.Contains(html, "Review pending replacement") != (row.Pending != nil) || strings.Contains(html, "View confirmation evidence") != (row.ConfirmedRenewalID != "") {
				t.Fatal("candidate and confirmation evidence conflated")
			}
			if state == "expired" && (!strings.Contains(html, "Certificate expired") || !strings.Contains(html, "Certificate valid · Expires")) {
				t.Fatal("valid replacement hid expired current identity")
			}
			if state == "empty" && (!strings.Contains(html, "No Windows certificate authority is configured") || !strings.Contains(html, "No devices match")) {
				t.Fatal("empty health scope missing")
			}
			if strings.Contains(html, "<script>Device</script>") || strings.Contains(html, `method="post"`) {
				t.Fatal("health view did not escape data or introduced mutation")
			}
			writeWindowsBrowserFixture(t, "windows-health-"+state, out.Bytes())
			if dir := os.Getenv("OPENUEM_WINDOWS_HEALTH_VIEW_ARTIFACTS"); dir != "" {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "health-"+state+".html"), out.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
