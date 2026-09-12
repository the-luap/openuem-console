package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/software/winget"
)

func exerciseWindowsSoftwareSources(t *testing.T, h *Handler, ctx context.Context, tenant, site int, version, installerKind string, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	base := fmt.Sprintf("/tenant/%d/software/catalog/%s", tenant, version)
	scoped := fmt.Sprintf("/tenant/%d/site/%d/software/catalog/%s/sources", tenant, site, version)
	path := base + "/sources"
	prior := h.winGetSource
	defer func() { h.winGetSource = prior }()
	calls := 0
	h.winGetSource = func(ctx context.Context, c winget.Coordinate) (*winget.Snapshot, error) {
		calls++
		content := fmt.Sprintf("PackageIdentifier: %s\nPackageVersion: %s\nInstallerType: wix\nScope: machine\nInstallers:\n- Architecture: x64\n  InstallerUrl: https://packages.example.test/private-source.msi?token=source-route-secret\n  InstallerSha256: %s\n  ProductCode: '{AABBCCDD-0000-4000-8000-000000000001}'\nManifestType: installer\nManifestVersion: 1.12.0\n", c.Identifier, c.Version, strings.Repeat("a", 64))
		if installerKind == "burn" {
			content = strings.ReplaceAll(strings.ReplaceAll(content, "InstallerType: wix", "InstallerType: burn"), ".msi", ".exe")
		}
		sum := sha256.Sum256([]byte(content))
		return &winget.Snapshot{Coordinate: c, Commit: strings.Repeat("a", 40), Path: "manifests/v/Vendor/RouteEditor/1.2.3/Vendor.RouteEditor.installer.yaml", SHA256: hex.EncodeToString(sum[:]), Content: []byte(content)}, ctx.Err()
	}
	safe := func(rec *httptest.ResponseRecorder) {
		t.Helper()
		for _, private := range []string{"source-route-secret", "private-source.msi", "private-source.exe", "InstallerUrl:", "BEGIN CERTIFICATE"} {
			if strings.Contains(rec.Body.String(), private) {
				t.Fatal("source response exposed private manifest content")
			}
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("source response was cacheable")
		}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin"} {
		rec := request(user, "GET", scoped, nil)
		safe(rec)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "Save installer source") {
			t.Fatal("site history or mutation boundary", user, rec.Code)
		}
	}
	rec := request("organization-admin", "GET", path, nil)
	safe(rec)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Save installer source") {
		t.Fatal("organization source capture unavailable", rec.Code)
	}
	form := func() url.Values { return url.Values{"request_id": {uuid.NewString()}, "confirmed": {"yes"}} }
	for _, change := range []func(url.Values){func(f url.Values) { f.Del("confirmed") }, func(f url.Values) { f.Add("request_id", uuid.NewString()) }, func(f url.Values) { f.Set("source_url", "https://foreign.invalid/a.yaml") }, func(f url.Values) { f.Set("request_id", "invalid") }} {
		f := form()
		change(f)
		rec = request("organization-admin", "POST", path, f)
		safe(rec)
		if rec.Code != 400 {
			t.Fatal("ambiguous capture accepted", rec.Code)
		}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin"} {
		if rec = request(user, "POST", scoped, form()); rec.Code != 403 {
			t.Fatal("site capture admitted", user, rec.Code)
		}
	}
	f := form()
	f.Set("csrf", "wrong")
	if rec = request("organization-admin", "POST", path, f); rec.Code != 403 {
		t.Fatal("source CSRF bypass", rec.Code)
	}
	f = form()
	f.Set("request_id", strings.Repeat("x", 9000))
	if rec = request("organization-admin", "POST", path, f); rec.Code != 403 {
		t.Fatal("unbounded source body", rec.Code)
	}
	if rec = request("organization-admin", "POST", path+"?confirmed=yes", form()); rec.Code != 400 {
		t.Fatal("source query altered capture", rec.Code)
	}
	if calls != 0 {
		t.Fatal("invalid capture contacted source")
	}
	capture := form()
	for range 2 {
		rec = request("organization-admin", "POST", path, capture)
		if rec.Code != 303 || rec.Header().Get("Location") != path+"/"+capture.Get("request_id")+"/review" {
			t.Fatal("capture/retry failed", rec.Code, rec.Body.String())
		}
	}
	if calls != 1 {
		t.Fatal("exact retry fetched a mutable source again")
	}
	source := path + "/" + capture.Get("request_id")
	review := source + "/review"
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec = request(user, "GET", scoped+"/"+capture.Get("request_id")+"/review", nil); rec.Code != 403 {
			t.Fatal("reader received approval review", rec.Code)
		}
	}
	rec = request("organization-admin", "GET", review, nil)
	safe(rec)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "packages.example.test") {
		t.Fatal("source review missing compatible host", rec.Code, rec.Body.String())
	}
	if installerKind == "burn" && (!strings.Contains(rec.Body.String(), "Required Burn bundle code") || !strings.Contains(rec.Body.String(), "same pinned bundle")) {
		t.Fatal("Burn review omitted its exact registration or removal behavior")
	}
	approval := url.Values{"confirmed": {"yes"}}
	for _, name := range []string{"approval_id", "installer_index", "review_hash"} {
		match := regexp.MustCompile(`name="` + name + `" value="([^"]+)"`).FindStringSubmatch(rec.Body.String())
		if len(match) != 2 {
			t.Fatal("source approval binding missing", name)
		}
		approval.Set(name, match[1])
	}
	clone := func() url.Values {
		f := url.Values{}
		for k, v := range approval {
			f[k] = append([]string(nil), v...)
		}
		return f
	}
	for _, change := range []func(url.Values){func(f url.Values) { f.Del("confirmed") }, func(f url.Values) { f.Add("approval_id", uuid.NewString()) }, func(f url.Values) { f.Set("installer_index", "00") }, func(f url.Values) { f.Set("installer_index", "256") }, func(f url.Values) { f.Set("review_hash", "invalid") }, func(f url.Values) { f.Set("arguments", "arbitrary") }} {
		f := clone()
		change(f)
		rec = request("organization-admin", "POST", source+"/approve", f)
		safe(rec)
		if rec.Code != 400 {
			t.Fatal("ambiguous source approval accepted", rec.Code)
		}
	}
	f = clone()
	f.Set("review_hash", strings.Repeat("b", 64))
	if rec = request("organization-admin", "POST", source+"/approve", f); rec.Code != 409 {
		t.Fatal("stale source review accepted", rec.Code)
	}
	f = clone()
	f.Set("csrf", "wrong")
	if rec = request("organization-admin", "POST", source+"/approve", f); rec.Code != 403 {
		t.Fatal("source approval CSRF bypass", rec.Code)
	}
	f = clone()
	f.Set("review_hash", strings.Repeat("a", 9000))
	if rec = request("organization-admin", "POST", source+"/approve", f); rec.Code != 403 {
		t.Fatal("unbounded approval body", rec.Code)
	}
	if rec = request("organization-admin", "POST", source+"/approve?installer_index=0", clone()); rec.Code != 400 {
		t.Fatal("query changed source approval", rec.Code)
	}
	var derived string
	for range 2 {
		rec = request("organization-admin", "POST", source+"/approve", clone())
		if rec.Code != 303 {
			t.Fatal("source approval/retry failed", rec.Code, rec.Body.String())
		}
		if derived != "" && derived != rec.Header().Get("Location") {
			t.Fatal("source approval retry changed revision")
		}
		derived = rec.Header().Get("Location")
	}
	derivedID := derived[strings.LastIndex(derived, "/")+1:]
	for _, suffix := range []string{"", "/" + capture.Get("request_id")} {
		rec = request("scoped-viewer", "GET", scoped+suffix, nil)
		safe(rec)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), derivedID) || strings.Contains(rec.Body.String(), "Review installer choices") {
			t.Fatal("reader source evidence missing", rec.Code, rec.Body.String())
		}
	}
	derivedScoped := fmt.Sprintf("/tenant/%d/site/%d/software/catalog/%s", tenant, site, derivedID)
	rec = request("scoped-viewer", "GET", derivedScoped, nil)
	safe(rec)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), scoped+"/"+capture.Get("request_id")) {
		t.Fatal("derived detail lost scoped provenance", rec.Code, rec.Body.String())
	}
	var storedKind string
	if err := h.Model.DB.QueryRowContext(ctx, `SELECT kind FROM uem_software_versions WHERE id=$1`, derivedID).Scan(&storedKind); err != nil || installerKind == "burn" && storedKind != "windows-burn" || installerKind == "wix" && storedKind != "windows-msi" {
		t.Fatal("source approval changed the explicit adapter kind", err)
	}
	var tasks int
	if err := h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_windows_software_requests WHERE version_id=$1`, derivedID).Scan(&tasks); err != nil || tasks != 0 {
		t.Fatal("source approval prepared a device operation", err)
	}
	if rec = request("organization-admin", "POST", derived+"/withdraw", url.Values{"confirmed": {"yes"}}); rec.Code != 303 {
		t.Fatal("derived withdrawal failed", rec.Code)
	}
	rec = request("scoped-viewer", "GET", scoped+"/"+capture.Get("request_id"), nil)
	safe(rec)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "derived installer approval was withdrawn") {
		t.Fatal("withdrawal erased source history", rec.Code)
	}
	h.winGetSource = func(context.Context, winget.Coordinate) (*winget.Snapshot, error) {
		return nil, fmt.Errorf("source-route-secret: %w", winget.ErrSource)
	}
	rec = request("organization-admin", "POST", path, form())
	safe(rec)
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "temporarily unavailable") {
		t.Fatal("source error lost safe retry guidance", rec.Code)
	}
}
