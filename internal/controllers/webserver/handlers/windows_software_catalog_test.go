package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func exerciseWindowsSoftwareCatalog(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	org := fmt.Sprintf("/tenant/%d/software/catalog", tenant)
	scoped := fmt.Sprintf("/tenant/%d/site/%d/software/catalog", tenant, site)
	form := func(kind string) url.Values {
		f := url.Values{"request_id": {uuid.NewString()}, "kind": {kind}, "name": {"Windows <Editor>"}, "identifier": {"Vendor.RouteEditor"}, "version": {"1.2.3"}, "architecture": {"x86_64"}, "minimum_os": {"10.0.26100"}, "detection_kind": {"msi-product"}, "product_code": {"{AABBCCDD-0000-4000-8000-000000000001}"}, "detection_version": {"1.2.3"}, "success_codes": {"0"}, "confirmed": {"yes"}}
		if kind != "windows-winget" {
			f.Set("sha256", strings.Repeat("a", 64))
			f.Set("reboot_codes", "3010")
		}
		if kind == "windows-msi" {
			f.Set("source_url", "https://packages.example.test/owned.msi?private=route-secret")
			f.Set("msi_properties", "LICENSEKEY=route-license")
		}
		if kind == "windows-exe" {
			f.Set("source_url", "https://packages.example.test/owned.exe?private=route-secret")
			f.Set("install_arguments", "/quiet\nroute-install-argument")
			f.Set("uninstall_url", "https://packages.example.test/remove.exe?private=route-remove")
			f.Set("uninstall_sha256", strings.Repeat("b", 64))
			f.Set("uninstall_arguments", "/quiet\nroute-remove-argument")
		}
		return f
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "GET", scoped+"/windows/new", nil); rec.Code != 403 {
			t.Fatal("reader opened approval form", user, rec.Code)
		}
		if rec := request(user, "POST", scoped+"/windows", form("windows-msi")); rec.Code != 403 {
			t.Fatal("reader approved executable", user, rec.Code)
		}
	}
	for _, kind := range []string{"windows-winget", "windows-msi", "windows-exe"} {
		if rec := request("organization-admin", "GET", org+"/windows/new?kind="+kind, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), `name="request_id"`) {
			t.Fatal("approval form unavailable", kind, rec.Code, rec.Body.String())
		}
		f := form(kind)
		rec := request("organization-admin", "POST", org+"/windows", f)
		if rec.Code != 303 {
			t.Fatal("Windows approval failed", kind, rec.Code, rec.Body.String())
		}
		location := rec.Header().Get("Location")
		version := strings.TrimPrefix(location, org+"/")
		if _, err := uuid.Parse(version); err != nil {
			t.Fatal(err)
		}
		if rec = request("organization-admin", "POST", org+"/windows", f); rec.Code != 303 || rec.Header().Get("Location") != location {
			t.Fatal("approval retry created another revision", rec.Code)
		}
		for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin"} {
			rec = request(user, "GET", scoped+"/"+version, nil)
			body := rec.Body.String()
			if rec.Code != 200 || !strings.Contains(body, "Windows &lt;Editor&gt;") || strings.Contains(body, "Install on a Mac") || strings.Contains(body, "Request installation") || strings.Contains(body, "route-secret") || strings.Contains(body, "route-license") || strings.Contains(body, "route-install-argument") || strings.Contains(body, "packages.example.test") || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("unsafe Windows detail", user, rec.Code)
			}
		}
		f.Set("version", "changed")
		if rec = request("organization-admin", "POST", org+"/windows", f); rec.Code != 409 {
			t.Fatal("approval request rebound", rec.Code)
		}
		if kind == "windows-msi" {
			exerciseWindowsSoftwareRequests(t, h, ctx, tenant, site, version, request)
		}
		if kind == "windows-winget" {
			exerciseWindowsSoftwareSources(t, h, ctx, tenant, site, version, "wix", request)
		}
		if rec = request("organization-admin", "POST", org+"/"+version+"/withdraw", url.Values{"confirmed": {"yes"}}); rec.Code != 303 {
			t.Fatal("Windows withdrawal failed", rec.Code)
		}
		if rec = request("scoped-viewer", "GET", scoped+"/"+version, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Withdrawn at") {
			t.Fatal("withdrawal missing", rec.Code)
		}
	}
	burn := form("windows-winget")
	burn.Set("detection_kind", "uninstall-key")
	burn.Set("uninstall_key", burn.Get("product_code"))
	burn.Del("product_code")
	burn.Set("registry_view", "64")
	rec := request("organization-admin", "POST", org+"/windows", burn)
	if rec.Code != 303 {
		t.Fatal("Burn source approval intent unavailable", rec.Code)
	}
	burnVersion := strings.TrimPrefix(rec.Header().Get("Location"), org+"/")
	exerciseWindowsSoftwareSources(t, h, ctx, tenant, site, burnVersion, "burn", request)
	burn.Set("request_id", uuid.NewString())
	burn.Set("kind", "windows-burn")
	burn.Set("sha256", strings.Repeat("a", 64))
	burn.Set("source_url", "https://packages.example.test/owned.exe")
	burn.Set("uninstall_url", burn.Get("source_url"))
	burn.Set("uninstall_sha256", burn.Get("sha256"))
	burn.Set("install_arguments", "/quiet\n/norestart")
	burn.Set("uninstall_arguments", "/uninstall\n/quiet\n/norestart")
	burn.Set("reboot_codes", "3010")
	if rec = request("organization-admin", "POST", org+"/windows", burn); rec.Code != 400 || !strings.Contains(rec.Body.String(), "saved WinGet source review") {
		t.Fatal("direct Burn publication bypassed source review", rec.Code)
	}
	for _, change := range []func(url.Values){
		func(f url.Values) { f.Del("confirmed") }, func(f url.Values) { f.Add("source_url", "https://foreign.example.test/a.msi") }, func(f url.Values) { f.Set("msi_properties", "LICENSEKEY=first\nLICENSEKEY=second") }, func(f url.Values) { f.Set("msi_properties", "REBOOT=Force") }, func(f url.Values) { f.Set("request_id", "invalid") }, func(f url.Values) { f.Set("unexpected", "private-extra") }, func(f url.Values) { f.Set("source_url", "http://insecure.example.test/a.msi") },
	} {
		f := form("windows-msi")
		change(f)
		rec := request("organization-admin", "POST", org+"/windows", f)
		if rec.Code != 400 || strings.Contains(rec.Body.String(), "route-secret") || strings.Contains(rec.Body.String(), "route-license") {
			t.Fatal("invalid approval accepted or exposed values", rec.Code)
		}
	}
	f := form("windows-msi")
	f.Set("csrf", "wrong")
	if rec := request("organization-admin", "POST", org+"/windows", f); rec.Code != 403 {
		t.Fatal("approval CSRF bypass", rec.Code)
	}
	if rec := request("organization-admin", "POST", org+"/windows?kind=windows-exe", form("windows-msi")); rec.Code != 400 {
		t.Fatal("query altered approval", rec.Code)
	}
	if rec := request("scoped-viewer", "GET", scoped+"?platform=windows&q=Windows", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Windows &lt;Editor&gt;") || strings.Contains(rec.Body.String(), "Approve a Windows package") {
		t.Fatal("shared Windows catalog unavailable", rec.Code)
	}
	if rec := request("scoped-viewer", "GET", scoped+"?platform=windows&q=%25", nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "Windows &lt;Editor&gt;") {
		t.Fatal("catalog wildcard was not literal", rec.Code)
	}
	for _, query := range []string{"platform=unknown", "q=" + strings.Repeat("a", 129)} {
		if rec := request("scoped-viewer", "GET", scoped+"?"+query, nil); rec.Code != 400 || !strings.Contains(rec.Body.String(), "package search") {
			t.Fatal("invalid shared catalog query lost guidance", rec.Code)
		}
	}
}

func TestWindowsSoftwareFormValuesAreLiteralAndBounded(t *testing.T) {
	args := softwareArgumentLines("first argument\r\n'quoted;&'\r\nlast\n")
	if len(args) != 3 || args[0] != "first argument" || args[1] != "'quoted;&'" || args[2] != "last" {
		t.Fatal("arguments changed", args)
	}
	for _, bad := range []string{"-1", "0x100000000", "abc", strings.Repeat("0,", 16) + "1"} {
		if _, err := softwareExitCodes(bad); err == nil {
			t.Fatal("invalid exit codes accepted", bad)
		}
	}
	codes, err := softwareExitCodes("0, 3010, 0x8A15002B")
	if err != nil || len(codes) != 3 || codes[2] != 0x8A15002B {
		t.Fatal("exit code width lost", codes, err)
	}
}
