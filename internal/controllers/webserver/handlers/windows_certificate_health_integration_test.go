package handlers

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func exerciseWindowsCertificateHealth(t *testing.T, scope access.Scope, sibling int, deviceID string, renewal windows.CertificateRenewal, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	path := fmt.Sprintf("/tenant/%d/site/%d/windows/certificate-health", scope.TenantID, scope.SiteID)
	admin := "renewal-organization-admin"
	for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", scope.TenantID), fmt.Sprintf("/tenant/%d/site/%d", scope.TenantID, scope.SiteID)} {
		for _, user := range []string{"renewal-viewer", "renewal-operator"} {
			if w := request(user, "GET", prefix+"/windows/certificate-health", nil); w.Code != 403 {
				t.Fatal("certificate health admitted scoped role", user, w.Code)
			}
		}
		w := request(admin, "GET", prefix+"/windows/certificate-health?filter=pending", nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), deviceID) || !strings.Contains(w.Body.String(), "/renewals/"+renewal.ID) {
			t.Fatal("scoped pending health unavailable", w.Code)
		}
		for _, want := range []string{"Replacement pending confirmation", "Current confirmed certificate expires", fmt.Sprintf("/tenant/%d/site/%d/windows/%s/renewals/%s", scope.TenantID, scope.SiteID, deviceID, renewal.ID)} {
			if !strings.Contains(w.Body.String(), want) {
				t.Fatal("health lifecycle/link missing", want)
			}
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "strict-origin" {
			t.Fatal("certificate health can be cached or leaked through referrer")
		}
		artifact("windows-certificate-health-pending", w)
	}
	for _, suffix := range []string{"?", "?filter=unknown", "?days=0", "?days=366", "?days=01", "?days=1&days=2", "?offset=100001", "?q=%0A", "?q=%zz", "?tenant=2"} {
		if w := request(admin, "GET", path+suffix, nil); w.Code != 400 {
			t.Fatal("invalid certificate health filters reached store", suffix, w.Code)
		}
	}
	for _, target := range []string{path + "?offset=1", path + "?q=%25", fmt.Sprintf("/tenant/%d/site/%d/windows/certificate-health?filter=all", scope.TenantID, sibling)} {
		w := request(admin, "GET", target, nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), deviceID) || !strings.Contains(w.Body.String(), "No devices match these certificate health filters.") {
			t.Fatal("scope, pagination or literal search leaked a device", w.Code)
		}
	}
	if w := request("organization-admin", "GET", path, nil); w.Code != 404 {
		t.Fatal("foreign organization accessed certificate health", w.Code)
	}
	for _, user := range []string{admin, "renewal-viewer", "renewal-operator"} {
		w := request(user, "GET", fmt.Sprintf("/tenant/%d/site/%d/windows/%s", scope.TenantID, scope.SiteID, deviceID), nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), ">Certificate health</a>") != (user == admin) {
			t.Fatal("certificate health navigation ignored role", user, w.Code)
		}
	}
}
