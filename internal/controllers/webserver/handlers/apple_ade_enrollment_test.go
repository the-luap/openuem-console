package handlers

import (
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestADEEnrollmentFormsRejectAmbiguityAndScopeChanges(t *testing.T) {
	for _, raw := range []string{"csrf=x&confirmed=yes&operation=retry&operation=disable", "csrf=x&confirmed=yes&unknown=value", "confirmed=yes", "csrf=x", "csrf=x&confirmed=no", "csrf=x&confirmed=yes&serials=" + strings.Repeat("x", 129<<10)} {
		r := httptest.NewRequest("POST", "/ios/ade", strings.NewReader(raw))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		c := echo.New().NewContext(r, httptest.NewRecorder())
		if _, err := adeEnrollmentForm(c, "operation", "serials"); err == nil {
			t.Fatal("invalid body accepted")
		}
	}
	for _, suffix := range []string{"?operation=disable", "?"} {
		r := httptest.NewRequest("POST", "/ios/ade"+suffix, strings.NewReader("csrf=x&confirmed=yes&operation=retry"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if _, err := adeEnrollmentForm(echo.New().NewContext(r, httptest.NewRecorder()), "operation"); err == nil {
			t.Fatal("query accepted")
		}
	}
	f := url.Values{"site_id": {"2"}, "name": {"Company Mac"}, "platform": {"macos"}, "removal": {"disallowed"}, "await_configuration": {"yes"}, "skip_setup_items": {"Siri, Appearance\nScreenTime"}}
	if _, err := adeProfileOptions(f, 1); err == nil {
		t.Fatal("URL scope changed by body")
	}
	o, err := adeProfileOptions(f, 0)
	if err != nil || o.SiteID != 2 || o.Removable || !o.AwaitConfiguration || len(o.SkipSetupItems) != 3 {
		t.Fatal("profile options lost", err)
	}
	f.Set("auto_advance", "true")
	if _, err = adeProfileOptions(f, 0); err == nil {
		t.Fatal("unrecognized boolean accepted")
	}
	f.Del("auto_advance")
	f.Set("removal", "")
	if _, err = adeProfileOptions(f, 0); err == nil {
		t.Fatal("removal rights were implicit")
	}
	if strings.Contains(adeWorkflowFailure(errors.New("synthetic private admission")).Error(), "synthetic private") {
		t.Fatal("workflow error leaked private details")
	}
	for _, prefix := range []string{"", "/tenant/:tenant", "/tenant/:tenant/site/:site"} {
		cap, ok := appleCapability("POST", prefix+"/ios/:id/setup/retry")
		if !ok || cap != access.EnrollDevices {
			t.Fatal("setup retry route lacks exact capability")
		}
	}
}
