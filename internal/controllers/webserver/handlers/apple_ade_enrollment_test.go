package handlers

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestADERequiredApplicationForms(t *testing.T) {
	for _, count := range []int{1, 2, 16, 17} {
		f := url.Values{"csrf": {"x"}, "confirmed": {"yes"}, "site_id": {"1"}, "platform": {"macos"}, "removal": {"disallowed"}, "await_configuration": {"yes"}}
		for i := range count {
			f.Add("required_applications", fmt.Sprintf("90000000-0000-4000-8000-%012d", i+1))
		}
		r := httptest.NewRequest("POST", "/ios/ade", strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		form, err := adeEnrollmentForm(echo.New().NewContext(r, httptest.NewRecorder()), "required_applications", "site_id", "platform", "removal", "await_configuration")
		if count > 16 {
			if err == nil {
				t.Fatal("unbounded selection accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		o, err := adeProfileOptions(form, 1)
		if err != nil || len(o.RequiredApplications) != count {
			t.Fatal("selected revisions lost", err)
		}
	}
	for _, raw := range []string{"csrf=x&confirmed=yes&version=a&version=b", "csrf=x&confirmed=yes&required_applications=a&required_applications=b"} {
		r := httptest.NewRequest("POST", "/ios/ade", strings.NewReader(raw))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if _, err := adeEnrollmentForm(echo.New().NewContext(r, httptest.NewRecorder()), "version", "reason"); err == nil {
			t.Fatal("replacement accepted ambiguous or unrelated app fields")
		}
	}
	for _, prefix := range []string{"", "/tenant/:tenant", "/tenant/:tenant/site/:site"} {
		for _, route := range []struct {
			method, path string
			cap          access.Capability
		}{{"GET", "/ios/ade/software", access.ManageCertificates}, {"GET", "/ios/:id/setup/applications/:requirement/history", access.ReadSoftware}, {"POST", "/ios/:id/setup/applications/:requirement/replace", access.ManageCertificates}} {
			if cap, ok := appleCapability(route.method, prefix+route.path); !ok || cap != route.cap {
				t.Fatal("required app route permission missing", route.path)
			}
		}
	}
}

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

func TestADEManagedAdministratorOptions(t *testing.T) {
	f := url.Values{"site_id": {"1"}, "platform": {"macos"}, "removal": {"disallowed"}, "await_configuration": {"yes"}, "manage_admin": {"yes"}, "admin_short_name": {"localadmin"}, "admin_full_name": {"Managed Admin"}, "admin_primary_account": {"standard"}, "admin_rotation_days": {"30"}, "admin_hidden": {"yes"}}
	o, err := adeProfileOptions(f, 1)
	if err != nil || o.MacAdmin == nil || !o.MacAdmin.Hidden || o.MacAdmin.RotationDays != 30 {
		t.Fatal("account policy lost", err)
	}
	for _, change := range []struct{ key, value string }{{"platform", "ios"}, {"await_configuration", ""}, {"admin_short_name", "root"}, {"admin_rotation_days", "-1"}, {"admin_rotation_days", "366"}, {"admin_rotation_days", "bad"}, {"admin_primary_account", "invalid"}, {"admin_hidden", "false"}, {"manage_admin", "false"}} {
		next := url.Values{}
		for key, value := range f {
			next[key] = append([]string(nil), value...)
		}
		next.Set(change.key, change.value)
		if _, err = adeProfileOptions(next, 1); err == nil {
			t.Fatal("invalid account policy accepted", change.key)
		}
	}
}
