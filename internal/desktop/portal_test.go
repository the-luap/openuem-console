package desktop

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment/registry"
)

func newPortalFixture(t *testing.T) *publicFixture {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	return newPublicFixtureWithAgent(t, true, key)
}

func TestDesktopPortalAndInvitationDownloadNeverClaimOrReserveAnIdentity(t *testing.T) {
	f := newPortalFixture(t)
	path := strings.TrimSuffix(f.path(""), "/")
	for _, method := range []string{"GET", "HEAD", "GET"} {
		response, data := publicRequest(t, f.server.Client(), f.server.URL, method, path, nil, nil)
		if response.StatusCode != 200 || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/html") || len(response.Cookies()) != 0 {
			t.Fatal("read-only portal did not return private browser instructions", response.StatusCode)
		}
		digest := sha256.Sum256([]byte(portalCSS))
		policy := response.Header.Get("Content-Security-Policy")
		if !strings.Contains(policy, "style-src 'sha256-"+base64.StdEncoding.EncodeToString(digest[:])+"'") || !strings.Contains(policy, "form-action 'none'") || !strings.Contains(policy, "frame-ancestors 'none'") || response.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Fatal("portal lost its restrictive browser policy")
		}
		if method == "HEAD" {
			if len(data) != 0 || response.ContentLength <= 0 {
				t.Fatal("portal HEAD has no representation length or returned a body")
			}
		} else if !strings.Contains(string(data), "Test organization") || !strings.Contains(string(data), "Windows (x64)") || !strings.Contains(string(data), "Download approved agent") || strings.Contains(string(data), "<script") || strings.Contains(string(data), "<form") {
			t.Fatal("portal lacks bounded native instructions or offers browser enrollment")
		}
		if method != "HEAD" && !bytes.Contains(data, []byte("<style>"+portalCSS+"</style>")) {
			t.Fatal("rendered styles do not match their CSP hash")
		}
		if method == "GET" && os.Getenv("OPENUEM_DESKTOP_PORTAL_ARTIFACTS") != "" {
			directory := os.Getenv("OPENUEM_DESKTOP_PORTAL_ARTIFACTS")
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "desktop-portal.html"), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		response, token := publicRequest(t, f.server.Client(), f.server.URL, method, f.path("invitation"), nil, nil)
		if response.StatusCode != 200 || response.ContentLength != 44 || response.Header.Get("Content-Disposition") != `attachment; filename="openuem-invitation.txt"` {
			t.Fatal("invitation attachment headers are incorrect", response.StatusCode)
		}
		if method == "HEAD" {
			if len(token) != 0 {
				t.Fatal("invitation HEAD returned a bearer token")
			}
		} else if string(token) != f.request.Invitation+"\n" {
			t.Fatal("download changed the original invitation")
		}
	}
	var uses, identities int
	if err := f.store.db.QueryRow(`SELECT (SELECT uses FROM uem_agent_invitations WHERE id=$1),(SELECT count(*) FROM uem_agent_identities)`, f.invitation.ID).Scan(&uses, &identities); err != nil || uses != 0 || identities != 0 {
		t.Fatal("scanner-safe reads issued or reserved identity", uses, identities, err)
	}
}

func TestOnlyPortalTopLevelNavigationAcceptsCrossSiteFetchMetadata(t *testing.T) {
	f := newPortalFixture(t)
	path := strings.TrimSuffix(f.path(""), "/")
	for _, test := range []struct {
		path, method, site, mode, destination, origin string
		status                                        int
	}{
		{path, "GET", "cross-site", "navigate", "document", "", 200},
		{path, "HEAD", "same-site", "navigate", "document", "", 200},
		{path, "GET", "cross-site", "cors", "empty", "", 403},
		{path, "GET", "cross-site", "navigate", "iframe", "", 403},
		{path, "GET", "unknown", "navigate", "document", "", 403},
		{path, "GET", "cross-site", "navigate", "document", "https://other.example.test", 403},
		{f.path("invitation"), "GET", "cross-site", "navigate", "document", "", 403},
		{f.path("configuration"), "GET", "cross-site", "navigate", "document", "", 403},
		{f.path("metadata"), "GET", "cross-site", "navigate", "document", "", 403},
		{f.path("claim"), "POST", "cross-site", "navigate", "document", "", 403},
		{path, "POST", "same-origin", "navigate", "document", "", 404},
	} {
		headers := map[string]string{"Sec-Fetch-Site": test.site, "Sec-Fetch-Mode": test.mode, "Sec-Fetch-Dest": test.destination}
		if test.origin != "" {
			headers["Origin"] = test.origin
		}
		response, _ := publicRequest(t, f.server.Client(), f.server.URL, test.method, test.path, nil, headers)
		if response.StatusCode != test.status {
			t.Fatal("browser navigation crossed a native-only boundary", test.path, test.method, test.site, test.mode, response.StatusCode)
		}
	}
}

func TestPortalExplainsCapacityRevocationAndUnavailableNativeSetup(t *testing.T) {
	f := newPortalFixture(t)
	path := strings.TrimSuffix(f.path(""), "/")
	if _, err := f.store.ClaimInstaller(context.Background(), f.catalog, *f.request, f.handler.origin); err != nil {
		t.Fatal(err)
	}
	response, data := publicRequest(t, f.server.Client(), f.server.URL, "GET", path, nil, nil)
	if response.StatusCode != 200 || !strings.Contains(string(data), "has reached its computer limit") || strings.Contains(string(data), ">Download approved agent</a>") || !strings.Contains(string(data), "Download invitation file") {
		t.Fatal("used invitation did not distinguish same-key recovery from new enrollment")
	}
	if err := f.store.Registry.RevokeInvitation(context.Background(), registry.Scope{TenantID: f.invitation.TenantID, SiteID: f.invitation.SiteID}, f.invitation.ID, "fixture-admin"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, f.path("invitation")} {
		response, data := publicRequest(t, f.server.Client(), f.server.URL, "GET", p, nil, nil)
		if response.StatusCode != 404 || strings.Contains(string(data), f.request.Invitation) || strings.Contains(string(data), "Test organization") {
			t.Fatal("revoked invitation exposed details or a download", response.StatusCode)
		}
	}
	preview := newPublicFixture(t)
	response, data = publicRequest(t, preview.server.Client(), preview.server.URL, "GET", strings.TrimSuffix(preview.path(""), "/"), nil, nil)
	if response.StatusCode != 200 || !strings.Contains(string(data), "Enrollment is not ready") || strings.Contains(string(data), ">Download approved agent</a>") {
		t.Fatal("preview release or missing signer offered native enrollment")
	}
}

func TestPortalRenderingEscapesLabelsAndBoundsItsOutput(t *testing.T) {
	h := &PublicHandler{}
	r := httptest.NewRequest(http.MethodGet, "https://uem.example.test", nil)
	w := httptest.NewRecorder()
	h.portalPage(w, r, 200, portalData{Available: true, Organization: `<script>alert("fixture")</script>`, Site: `<img src="https://other.example.test">`})
	if w.Code != 200 || strings.Contains(w.Body.String(), "<script>") || strings.Contains(w.Body.String(), "<img src=") || !strings.Contains(w.Body.String(), "&lt;script&gt;") {
		t.Fatal("stored portal labels escaped HTML context")
	}
	var b portalBuffer
	if _, err := io.WriteString(&b, strings.Repeat("a", 64<<10)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(&b, "x"); err == nil || b.Len() != 64<<10 {
		t.Fatal("rendering bypassed its limit through StringWriter")
	}
	w = httptest.NewRecorder()
	h.portalPage(w, r, 200, portalData{Available: true, Organization: strings.Repeat("a", 65<<10)})
	if w.Code != 503 || bytes.Contains(w.Body.Bytes(), []byte("<html")) {
		t.Fatal("oversized labels produced a partial successful portal")
	}
}

func TestPortalDoesNotOfferFilesForMetadataThatCannotProduceNativeConfiguration(t *testing.T) {
	f := newPortalFixture(t)
	if _, err := f.store.db.Exec(`UPDATE sites SET description=$1 WHERE id=$2`, "Invalid\nsite", f.invitation.SiteID); err != nil {
		t.Fatal(err)
	}
	response, data := publicRequest(t, f.server.Client(), f.server.URL, "GET", strings.TrimSuffix(f.path(""), "/"), nil, nil)
	if response.StatusCode != 200 || !strings.Contains(string(data), "Enrollment is not ready") || strings.Contains(string(data), "Download invitation file") {
		t.Fatal("invalid native configuration metadata offered downloads")
	}
	response, _ = publicRequest(t, f.server.Client(), f.server.URL, "GET", f.path("invitation"), nil, nil)
	if response.StatusCode != 404 {
		t.Fatal("invalid native configuration metadata returned a token file")
	}
}
