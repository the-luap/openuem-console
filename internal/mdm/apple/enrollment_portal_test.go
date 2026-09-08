package apple

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

var portalCSRFPattern = regexp.MustCompile(`name="csrf" value="([A-Za-z0-9_-]+)"`)

func portalRead(t *testing.T, response *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Referrer-Policy") != "strict-origin" {
		t.Fatal("enrollment response permits caching or referrer leakage")
	}
	return body
}

func portalPost(t *testing.T, client *http.Client, address, origin string, form url.Values) *http.Response {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, address, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func portalStart(t *testing.T, client *http.Client, address string) url.Values {
	t.Helper()
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	body := portalRead(t, response)
	if response.StatusCode != 200 || !bytes.Contains(body, []byte("Before you start")) {
		t.Fatal("instructions unavailable", response.StatusCode, string(body))
	}
	match := portalCSRFPattern.FindSubmatch(body)
	if len(match) != 2 {
		t.Fatal("missing enrollment CSRF field")
	}
	if !strings.Contains(response.Header.Get("Content-Security-Policy"), "default-src 'none'") || !strings.Contains(response.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("public enrollment lacks its script/frame boundary")
	}
	cookies := response.Cookies()
	if len(cookies) != 1 || cookies[0].Name != enrollmentBrowserCookie || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" || cookies[0].Domain != "" || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("enrollment cookie lacks browser protections")
	}
	return url.Values{"csrf": {string(match[1])}, "action": {"claim"}, "confirm": {"yes"}, "platform": {"ipados"}}
}

func portalFixture(t *testing.T, options ...EnrollmentOptions) (*Store, *httptest.Server, *Invitation, string) {
	t.Helper()
	s := testStore(t)
	testSettings(t, s, 1)
	server := httptest.NewTLSServer(s.ProtocolHandler(slog.New(slog.NewTextHandler(io.Discard, nil))))
	t.Cleanup(server.Close)
	if _, err := s.db.Exec(`UPDATE mdm_apple_settings SET public_url=$1`, server.URL); err != nil {
		t.Fatal(err)
	}
	option := EnrollmentOptions{}
	if len(options) == 1 {
		option = options[0]
	}
	invite, err := s.invite(context.Background(), Scope{TenantID: 1, SiteID: 1}, "Portal test", "admin", option, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, server, invite, invite.URL[strings.LastIndex(invite.URL, "/")+1:]
}

func savePortalArtifact(t *testing.T, name string, body []byte) {
	t.Helper()
	if dir := os.Getenv("OPENUEM_ENROLLMENT_UI_ARTIFACTS"); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".html"), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEnrollmentPortalDoesNotConsumeScannerReadsAndRequiresConfirmation(t *testing.T) {
	s, server, invite, _ := portalFixture(t)
	client := server.Client()
	for _, method := range []string{"GET", "GET", "HEAD", "HEAD"} {
		r, _ := http.NewRequest(method, invite.URL, nil)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body := portalRead(t, response)
		if response.StatusCode != 200 || (method == "HEAD" && len(body) != 0) || strings.Contains(response.Header.Get("Content-Type"), "aspen") {
			t.Fatal("scanner request retrieved a profile", method, response.StatusCode)
		}
		if method == "GET" {
			savePortalArtifact(t, "ready", body)
		}
	}
	var pending bool
	if err := s.db.QueryRow(`SELECT status='pending' AND certificate_fingerprint IS NULL AND invite_hash IS NOT NULL FROM mdm_apple_devices WHERE id=$1`, invite.DeviceID).Scan(&pending); err != nil || !pending {
		t.Fatal("a read consumed the invitation", err)
	}
	form := portalStart(t, client, invite.URL)
	for _, tc := range []struct {
		field, value, origin string
		code                 int
	}{
		{"csrf", "", server.URL, 403}, {"csrf", "forged", server.URL, 403},
		{"confirm", "", server.URL, 400}, {"platform", "windows", server.URL, 400},
		{"platform", "android", server.URL, 400}, {"platform", "ios", "https://attacker.example", 403},
		{"platform", "ios", "", 403},
		{"platform", "ios", "null", 403},
	} {
		bad := url.Values{}
		for key, value := range form {
			bad[key] = append([]string{}, value...)
		}
		bad.Set(tc.field, tc.value)
		response := portalPost(t, client, invite.URL, tc.origin, bad)
		body := portalRead(t, response)
		if response.StatusCode != tc.code {
			t.Fatal("unsafe claim accepted", tc, response.StatusCode, string(body))
		}
	}
	other := &http.Client{Transport: client.Transport}
	otherForm := portalStart(t, other, invite.URL)
	response := portalPost(t, client, invite.URL, server.URL, form)
	portalRead(t, response)
	if response.StatusCode != 303 {
		t.Fatal("confirmed claim failed", response.StatusCode)
	}
	response = portalPost(t, other, invite.URL, server.URL, otherForm)
	body := portalRead(t, response)
	if response.StatusCode != 409 || bytes.Contains(body, []byte("Test organization")) {
		t.Fatal("another browser took over or saw private status", response.StatusCode)
	}
	response = portalPost(t, client, invite.URL, server.URL, form)
	portalRead(t, response)
	if response.StatusCode != 303 {
		t.Fatal("duplicate claim was not idempotent", response.StatusCode)
	}
	response, err := client.Get(invite.URL)
	if err != nil {
		t.Fatal(err)
	}
	body = portalRead(t, response)
	savePortalArtifact(t, "claimed", body)
	if !bytes.Contains(body, []byte("3 download attempts")) {
		t.Fatal("claim did not offer bounded download")
	}
	var claims, audits int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_enrollment_claims`).Scan(&claims); err != nil || claims != 1 {
		t.Fatal("identity claim was duplicated", claims, err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE action='apple.enrollment.claim'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("claim audit missing or duplicated", audits, err)
	}
}

func TestEnrollmentHTTPRejectsMalformedAndCrossSiteForms(t *testing.T) {
	s, server, invite, _ := portalFixture(t)
	client := server.Client()
	form := portalStart(t, client, invite.URL)
	for _, tc := range []struct {
		name, contentType, body, query, fetchSite string
		noCookie                                  bool
		code                                      int
	}{
		{name: "oversized", contentType: "application/x-www-form-urlencoded", body: form.Encode() + "&extra=" + strings.Repeat("x", 9<<10), code: 400},
		{name: "content type", contentType: "text/plain", body: form.Encode(), code: 415},
		{name: "malformed encoding", contentType: "application/x-www-form-urlencoded", body: "csrf=%zz", code: 400},
		{name: "duplicate token", contentType: "application/x-www-form-urlencoded", body: form.Encode() + "&csrf=" + form.Get("csrf"), code: 403},
		{name: "query token", contentType: "application/x-www-form-urlencoded", body: form.Encode(), query: "?csrf=" + form.Get("csrf"), code: 404},
		{name: "cross site metadata", contentType: "application/x-www-form-urlencoded", body: form.Encode(), fetchSite: "cross-site", code: 403},
		{name: "missing browser", contentType: "application/x-www-form-urlencoded", body: form.Encode(), noCookie: true, code: 403},
	} {
		r, _ := http.NewRequest(http.MethodPost, invite.URL+tc.query, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.contentType)
		r.Header.Set("Origin", server.URL)
		r.Header.Set("Sec-Fetch-Site", tc.fetchSite)
		requestClient := client
		if tc.noCookie {
			requestClient = &http.Client{Transport: client.Transport}
		}
		response, err := requestClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		portalRead(t, response)
		if response.StatusCode != tc.code {
			t.Fatal(tc.name, response.StatusCode)
		}
	}
	var pending bool
	if err := s.db.QueryRow(`SELECT status='pending' AND certificate_fingerprint IS NULL FROM mdm_apple_devices WHERE id=$1`, invite.DeviceID).Scan(&pending); err != nil || !pending {
		t.Fatal("rejected form changed enrollment", err)
	}
}

func TestEnrollmentRetriesAreBoundedEncryptedAndSurviveRestart(t *testing.T) {
	s, _, invite, token := portalFixture(t)
	ctx := context.Background()
	browser, _ := randomToken()
	other, _ := randomToken()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, who := range []string{browser, other} {
		wg.Add(1)
		go func(who string) { defer wg.Done(); results <- s.ClaimEnrollment(ctx, token, who) }(who)
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal("concurrent browsers did not claim exactly once", success)
	}
	state, err := s.EnrollmentStatus(ctx, token, browser)
	if err != nil {
		t.Fatal(err)
	}
	if state.State == "used" {
		browser, other = other, browser
	}
	if _, err = s.DownloadEnrollment(ctx, token, other); !errors.Is(err, ErrNotFound) {
		t.Fatal("other browser retrieved profile", err)
	}
	var stored []byte
	if err = s.db.QueryRow(`SELECT profile FROM mdm_apple_enrollment_claims WHERE device_id=$1`, invite.DeviceID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("<?xml")) || bytes.Contains(stored, []byte("PayloadContent")) {
		t.Fatal("retry profile stored in plaintext")
	}
	inner, err := s.secrets.open(stored, secretPurpose(1, invite.DeviceID, "enrollment_retry"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(inner, []byte("PayloadContent")) {
		t.Fatal("server master key alone recovered browser retry identity")
	}
	wrongBox, err := enrollmentRetryBox(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrongBox.open(inner, secretPurpose(1, invite.DeviceID, "enrollment_retry")); err == nil {
		t.Fatal("another browser decrypted the retry identity")
	}
	restarted, err := NewStore(s.db, "integration-test-master-key-32-bytes-minimum")
	if err != nil {
		t.Fatal(err)
	}
	profiles := make(chan []byte, 8)
	errorsCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := restarted.DownloadEnrollment(ctx, token, browser)
			profiles <- data
			errorsCh <- err
		}()
	}
	wg.Wait()
	close(profiles)
	close(errorsCh)
	var first []byte
	for data := range profiles {
		if len(data) > 0 {
			if first == nil {
				first = data
			} else if !bytes.Equal(first, data) {
				t.Fatal("retry issued a different identity")
			}
		}
	}
	success = 0
	for err := range errorsCh {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	}
	if success != 3 {
		t.Fatal("retry limit was bypassed", success)
	}
	if err = s.db.QueryRow(`SELECT profile FROM mdm_apple_enrollment_claims WHERE device_id=$1`, invite.DeviceID).Scan(&stored); err != nil || stored != nil {
		t.Fatal("exhausted retry secret retained", err)
	}
	state, err = restarted.EnrollmentStatus(ctx, token, browser)
	if err != nil || state.State != "claimed" || state.DownloadsRemaining != 0 {
		t.Fatal("retry state incorrect", state, err)
	}
}

func TestEnrollmentExpiryAndRevocationCloseRetryAccess(t *testing.T) {
	s, _, invite, token := portalFixture(t)
	ctx := context.Background()
	browser, _ := randomToken()
	if _, err := s.db.Exec(`UPDATE mdm_apple_devices SET invite_expires_at=now()-interval '1 minute' WHERE id=$1`, invite.DeviceID); err != nil {
		t.Fatal(err)
	}
	state, err := s.EnrollmentStatus(ctx, token, browser)
	if err != nil || state.State != "expired" {
		t.Fatal(state, err)
	}
	if err = s.ClaimEnrollment(ctx, token, browser); !errors.Is(err, ErrConflict) {
		t.Fatal("expired invitation claimed", err)
	}
	for _, revoke := range []bool{false, true} {
		invite, err = s.Invite(ctx, Scope{TenantID: 1, SiteID: 1}, "Expiry", "admin")
		if err != nil {
			t.Fatal(err)
		}
		token = invite.URL[strings.LastIndex(invite.URL, "/")+1:]
		if err = s.ClaimEnrollment(ctx, token, browser); err != nil {
			t.Fatal(err)
		}
		if revoke {
			err = s.RevokeEnrollment(ctx, Scope{TenantID: 1, SiteID: 1}, invite.DeviceID, "admin")
		} else {
			_, err = s.db.Exec(`UPDATE mdm_apple_enrollment_claims SET download_expires_at=now()-interval '1 minute' WHERE device_id=$1`, invite.DeviceID)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.DownloadEnrollment(ctx, token, browser); !errors.Is(err, ErrNotFound) {
			t.Fatal("expired/revoked retry succeeded", revoke, err)
		}
		if err = s.CleanupEnrollmentClaims(ctx); err != nil {
			t.Fatal(err)
		}
		var removed bool
		if err = s.db.QueryRow(`SELECT profile IS NULL FROM mdm_apple_enrollment_claims WHERE device_id=$1`, invite.DeviceID).Scan(&removed); err != nil || !removed {
			t.Fatal("expired/revoked private key retained", err)
		}
	}
	if _, err = s.db.Exec(`UPDATE mdm_apple_enrollment_claims SET status_expires_at=now()-interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if err = s.CleanupEnrollmentClaims(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = s.EnrollmentStatus(ctx, token, browser); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired status retained", err)
	}
}

func TestMacEnrollmentPortalKeepsPlatformAndShowsMacInstructions(t *testing.T) {
	s, server, invite, token := portalFixture(t)
	client := server.Client()
	form := portalStart(t, client, invite.URL)
	form.Set("platform", "macos")
	response := portalPost(t, client, invite.URL, server.URL, form)
	portalRead(t, response)
	if response.StatusCode != 303 {
		t.Fatal("Mac claim rejected", response.StatusCode)
	}
	response, err := client.Get(invite.URL)
	if err != nil {
		t.Fatal(err)
	}
	body := portalRead(t, response)
	if response.StatusCode != 200 || !bytes.Contains(body, []byte("Open System Settings")) || bytes.Contains(body, []byte("eight minutes")) || bytes.Contains(body, []byte("VPN &amp; Device Management")) {
		t.Fatal("wrong platform instructions", response.StatusCode, string(body))
	}
	savePortalArtifact(t, "mac-enrollment", body)
	status, err := s.EnrollmentStatus(t.Context(), token, client.Jar.Cookies(response.Request.URL)[0].Value)
	if err != nil || status.Platform != PlatformMacOS {
		t.Fatal("platform did not persist", status, err)
	}
	response = portalPost(t, client, invite.URL, server.URL, form)
	portalRead(t, response)
	if response.StatusCode != 303 {
		t.Fatal("same-platform retry not idempotent", response.StatusCode)
	}
	form.Set("platform", "ios")
	response = portalPost(t, client, invite.URL, server.URL, form)
	portalRead(t, response)
	if response.StatusCode != 409 {
		t.Fatal("retry changed platform", response.StatusCode)
	}
	form.Set("action", "download")
	response = portalPost(t, client, invite.URL, server.URL, form)
	profile := portalRead(t, response)
	if response.StatusCode != 200 {
		t.Fatal("Mac profile unavailable", response.StatusCode)
	}
	if !bytes.Contains(profile, []byte("com.apple.mdm.bootstraptoken")) {
		t.Fatal("Mac enrollment lacks bootstrap capability")
	}
	_, cert := testSCEPEnrollHTTP(t, client, invite.DeviceID, profile)
	d, err := s.AuthenticateCertificate(t.Context(), invite.DeviceID, cert)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CheckIn(t.Context(), d, map[string]any{"MessageType": "Authenticate", "Topic": "com.apple.mgmt.test", "UDID": "mac-portal-test", "ProductName": "iPhone16,1", "OSVersion": "18.6"}); err == nil {
		t.Fatal("iPhone accepted Mac enrollment choice")
	}
	if err = s.CheckIn(t.Context(), d, map[string]any{"MessageType": "Authenticate", "Topic": "com.apple.mgmt.test", "UDID": "mac-portal-test", "Model": "Mac16,1", "ModelName": "MacBook Pro", "OSVersion": "15.0"}); err != nil {
		t.Fatal("Mac check-in rejected", err)
	}
}
