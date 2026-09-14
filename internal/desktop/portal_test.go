package desktop

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/bootstrap"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/desktop/protocol"
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

func TestLinuxPortalPreservesApprovedTargetThroughDownloadsAndClaim(t *testing.T) {
	for _, target := range []struct{ architecture, format, label string }{{"amd64", "deb", "Linux (x64)"}, {"arm64", "rpm", "Linux (ARM64)"}} {
		t.Run(target.architecture, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(private)
			f := newPublicTargetFixture(t, true, "linux", target.architecture, target.format, private)
			path := strings.TrimSuffix(f.path(""), "/")
			for _, method := range []string{"GET", "HEAD", "GET"} {
				response, data := publicRequest(t, f.server.Client(), f.server.URL, method, path, nil, nil)
				if response.StatusCode != 200 || response.ProtoMajor != 2 {
					t.Fatal("Linux portal unavailable over native TLS", response.StatusCode)
				}
				if method == "HEAD" {
					if len(data) != 0 {
						t.Fatal("Linux portal HEAD returned a body")
					}
				} else {
					for _, text := range []string{target.label, "Linux activation requires root access and systemd", "verifies the approved package publisher", "Download approved agent"} {
						if !bytes.Contains(data, []byte(text)) {
							t.Fatal("Linux portal omitted its target or native prerequisites", text)
						}
					}
					if bytes.Contains(data, []byte("Windows (")) || bytes.Contains(data, []byte("Login Items")) {
						t.Fatal("Linux invitation showed another platform's instructions")
					}
					if directory := os.Getenv("OPENUEM_DESKTOP_PORTAL_ARTIFACTS"); directory != "" {
						if os.MkdirAll(directory, 0700) != nil || os.WriteFile(filepath.Join(directory, "desktop-portal-linux-"+target.architecture+".html"), data, 0600) != nil {
							t.Fatal("could not write owned Linux portal artifact")
						}
					}
				}
			}
			response, configuration := publicRequest(t, f.server.Client(), f.server.URL, "GET", f.path("configuration"), nil, nil)
			verified, err := bootstrap.Verify(configuration, bootstrap.Trust{Origin: f.handler.origin, BootstrapKeys: []ed25519.PublicKey{public}, ReleaseKeys: []ed25519.PublicKey{f.public}, Platform: "linux", Architecture: target.architecture}, time.Now())
			if response.StatusCode != 200 || err != nil || verified.Artifact() != f.invitation.Artifact || verified.Config().TenantID != 1 || verified.Config().SiteID != 1 {
				t.Fatal("Linux portal configuration lost its signed target or scope", err)
			}
			response, packageBytes := publicRequest(t, f.server.Client(), f.server.URL, "GET", protocol.DownloadPath(f.invitation.ReleaseDigest, "linux", target.architecture), nil, nil)
			if response.StatusCode != 200 || verified.VerifyPackage(bytes.NewReader(packageBytes)) != nil || !strings.Contains(response.Header.Get("Content-Disposition"), f.invitation.Artifact.Filename) {
				t.Fatal("Linux download did not match the approved package")
			}
			var uses, identities int
			if err := f.store.db.QueryRow(`SELECT (SELECT uses FROM uem_agent_invitations WHERE id=$1),(SELECT count(*) FROM uem_agent_identities)`, f.invitation.ID).Scan(&uses, &identities); err != nil || uses != 0 || identities != 0 {
				t.Fatal("Linux browser reads consumed enrollment", err)
			}
			request, err := json.Marshal(f.request)
			if err != nil {
				t.Fatal(err)
			}
			var previous enrollment.Response
			for attempt := 0; attempt < 2; attempt++ {
				response, data := publicRequest(t, f.server.Client(), f.server.URL, "POST", f.path("claim"), request, map[string]string{"Content-Type": "application/json"})
				var issued enrollment.Response
				if response.StatusCode != 200 || json.Unmarshal(data, &issued) != nil || issued.TenantID != 1 || issued.SiteID != 1 || issued.DeviceID == "" || (attempt != 0 && (issued.DeviceID != previous.DeviceID || issued.Certificate != previous.Certificate)) {
					t.Fatal("Linux claim or retry lost its scoped individual identity", response.StatusCode)
				}
				previous = issued
			}
			var platform, architecture string
			if err := f.store.db.QueryRow(`SELECT platform,architecture FROM uem_agent_identities WHERE id=$1`, previous.DeviceID).Scan(&platform, &architecture); err != nil || platform != "linux" || architecture != target.architecture {
				t.Fatal("issued Linux identity lost its native target", err)
			}
		})
	}
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
