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

func TestWindowsRenewalViewsDistinguishCertificateAccessAndCompletion(t *testing.T) {
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
	info := &partials.CommonInfo{Principal: access.Principal{UserID: "synthetic-admin", Grants: []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}}, SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "11", CSRFToken: "synthetic-csrf"}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/11/windows/test/renewals/test", nil).WithContext(ctx), httptest.NewRecorder())
	now := time.Date(2026, 9, 10, 12, 13, 14, 123456000, time.UTC)
	device := windows.DeviceMetadata{ID: "10000000-0000-4000-8000-000000000001", Name: "<script>device</script>", CertificateExpiresAt: now.Add(time.Hour), RevokedAt: &now}
	for _, test := range []struct {
		phase              string
		replacementRevoked bool
		role               access.Role
		action             bool
	}{
		{"pending", false, access.TenantAdmin, true}, {"pending", true, access.TenantAdmin, false}, {"pending", false, access.Viewer, false}, {"confirmed", false, access.TenantAdmin, false}, {"confirmed", true, access.TenantAdmin, false}, {"canceled", true, access.TenantAdmin, false}, {"unexpected", false, access.TenantAdmin, false},
	} {
		t.Run(test.phase+"/"+string(test.role), func(t *testing.T) {
			info.Principal.Grants[0].Role = test.role
			detail := windows.CertificateRenewalDetail{Renewal: windows.CertificateRenewal{ID: "20000000-0000-4000-8000-000000000001", Phase: test.phase, Revision: 7, CreatedAt: now, CompletedAt: &now, ConfirmedSessionID: "synthetic-session", ConfirmedMessageID: 2}, Source: windows.RenewalCertificateMetadata{ID: "previous-certificate", FingerprintSHA256: strings.Repeat("ab", 32), IssuedAt: now, ExpiresAt: now.Add(time.Hour)}, Replacement: windows.RenewalCertificateMetadata{ID: "replacement-certificate", FingerprintSHA256: strings.Repeat("cd", 32), IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour)}, Resolution: "<script>reviewed reason</script>"}
			if test.replacementRevoked {
				detail.Replacement.RevokedAt = &now
			}
			if test.phase == "confirmed" {
				detail.Source.RevokedAt = &now
			}
			if test.phase == "pending" {
				detail.Renewal.CompletedAt = nil
			}
			var out bytes.Buffer
			if err := CertificateRenewal(c, info, device, detail).Render(ctx, &out); err != nil {
				t.Fatal(err)
			}
			html := out.String()
			for _, want := range []string{renewalState(test.phase), "Access revoked", "&lt;script&gt;device&lt;/script&gt;", "Previous certificate", "Replacement certificate", detail.Source.FingerprintSHA256, detail.Replacement.FingerprintSHA256, "2026-09-10 12:13:14.123456 UTC"} {
				if !strings.Contains(html, want) {
					t.Fatal("renewal lifecycle distinction missing", want)
				}
			}
			if strings.Contains(html, `name="confirm_cancel"`) != test.action {
				t.Fatal("renewal cancellation offered for the wrong role or state")
			}
			if test.action && (!strings.Contains(html, `name="expected_revision" value="7"`) || !strings.Contains(html, `name="csrf" value="synthetic-csrf"`)) {
				t.Fatal("cancellation lost reviewed revision or CSRF")
			}
			if strings.Contains(html, "Confirmation session ID") != (test.phase == "confirmed") {
				t.Fatal("confirmation evidence rendered for an unconfirmed replacement")
			}
			if test.phase == "confirmed" && (!strings.Contains(html, "synthetic-session") || !strings.Contains(html, "Later renewals may have replaced this certificate again.")) {
				t.Fatal("historical confirmation implied current access")
			}
			if strings.Contains(html, "&lt;script&gt;reviewed reason&lt;/script&gt;") != (test.phase == "canceled") {
				t.Fatal("cancellation resolution shown in the wrong phase")
			}
			for _, absent := range []string{"<script>device</script>", "<script>reviewed reason</script>"} {
				if strings.Contains(html, absent) {
					t.Fatal("untrusted renewal content was not escaped")
				}
			}
		})
	}
}
