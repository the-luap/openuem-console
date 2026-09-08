package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/openuem-console/internal/desktop"
)

func prepareDesktopInvitationCatalog(t *testing.T, h *Handler, ctx context.Context, sequence uint64) (*desktop.Catalog, *artifacts.Verified, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	directory := t.TempDir()
	catalog, err := desktop.NewCatalog(h.Model.DB, directory, []ed25519.PublicKey{public})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { catalog.Close() })
	content := []byte("non-executable console invitation package fixture")
	agent := []byte("separate final agent fixture")
	digest, agentDigest := sha256.Sum256(content), sha256.Sum256(agent)
	now := time.Now().UTC().Truncate(time.Second)
	manifest := artifacts.Manifest{Schema: 1, Sequence: sequence, Version: "0.12.0", PublishedAt: now.Add(-time.Hour), ExpiresAt: now.Add(2 * time.Hour), Artifacts: []artifacts.Artifact{
		{Platform: "windows", Architecture: "amd64", Format: "msi", Filename: "openuem-agent-0.12.0-windows-amd64.msi", Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]), AgentSize: int64(len(agent)), AgentSHA256: hex.EncodeToString(agentDigest[:])},
		// Older preview artifacts are excluded from native invitation forms.
		{Platform: "macos", Architecture: "arm64", Format: "pkg", Filename: "openuem-agent-0.12.0-macos-arm64.pkg", Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])},
	}}
	data, err := artifacts.Sign(manifest, private, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := artifacts.Verify(data, []ed25519.PublicKey{public}, now, artifacts.Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(directory, verified.Digest()), 0755); err != nil {
		t.Fatal(err)
	}
	for _, artifact := range manifest.Artifacts {
		if err := os.WriteFile(filepath.Join(directory, verified.Digest(), artifact.Filename), content, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := catalog.Accept(ctx, data, "isolated-release-admin"); err != nil {
		t.Fatal(err)
	}
	h.DesktopCatalog, h.DesktopBootstrapReady = catalog, true
	return catalog, verified, filepath.Join(directory, verified.Digest(), manifest.Artifacts[0].Filename)
}

func exerciseDesktopInvitationCreation(t *testing.T, h *Handler, ctx context.Context, tenantID, siteID, siblingID int, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	base := fmt.Sprintf("/tenant/%d/site/%d", tenantID, siteID)
	catalog, release, packagePath := prepareDesktopInvitationCatalog(t, h, ctx, 42)
	form := func() url.Values {
		return url.Values{"target": {"windows/amd64"}, "max_uses": {"1"}, "hours": {"24"}, "release_digest": {release.Digest()}, "confirm_create": {"yes"}, "csrf": {"console-test-token"}}
	}
	count := func() int {
		t.Helper()
		var n int
		if err := h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_agent_invitations`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	initial := count()
	t.Run("native invitation form follows scoped capabilities and compatible release targets", func(t *testing.T) {
		viewer := request("scoped-viewer", "GET", base+"/desktop/enrollment", nil)
		if viewer.Code != 200 || strings.Contains(viewer.Body.String(), "Create invitation</button>") {
			t.Fatal("viewer received enrollment creation controls", viewer.Code)
		}
		operator := request("scoped-operator", "GET", base+"/desktop/enrollment", nil)
		if operator.Code != 200 || !strings.Contains(operator.Body.String(), "Create invitation</button>") || !strings.Contains(operator.Body.String(), release.Digest()) || strings.Contains(operator.Body.String(), `value="macos/arm64"`) {
			t.Fatal("operator form did not select the compatible approved release", operator.Code)
		}
		artifact("desktop-create-invitation", operator)
		invitationForm := strings.Split(operator.Body.String(), `name="release_digest"`)
		if len(invitationForm) != 2 {
			t.Fatal("native invitation form was ambiguous")
		}
		selected := regexp.MustCompile(`<option[^>]*selected[^>]*>`).FindAllString(strings.Split(invitationForm[1], "</form>")[0], -1)
		if len(selected) != 1 || !strings.Contains(selected[0], `value="24"`) {
			t.Fatal("HTML boolean attributes changed the default target or one-day validity", selected)
		}
		if rec := request("scoped-viewer", "POST", base+"/desktop/invitations", form()); rec.Code != 403 {
			t.Fatal("viewer created invitation", rec.Code)
		}
		foreign := fmt.Sprintf("/tenant/%d/site/%d/desktop/invitations", tenantID, siblingID)
		if rec := request("scoped-operator", "POST", foreign, form()); rec.Code != 403 && rec.Code != 404 {
			t.Fatal("operator created foreign-site invitation", rec.Code)
		}
		if rec := request("scoped-operator", "GET", base+"/desktop/invitations", nil); rec.Code == 200 {
			t.Fatal("GET reached creation")
		}
		if count() != initial {
			t.Fatal("read or denied action created invitation")
		}
	})
	t.Run("invalid and ambiguous creation input cannot change scope or create state", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			change func(url.Values)
			status int
		}{
			{"csrf", func(f url.Values) { f.Set("csrf", "wrong") }, 403},
			{"confirmation", func(f url.Values) { f.Del("confirm_create") }, 400},
			{"duplicate scope selector", func(f url.Values) { f.Add("target", "macos/arm64") }, 400},
			{"duplicate csrf", func(f url.Values) { f.Add("csrf", "wrong") }, 400},
			{"foreign body site", func(f url.Values) { f.Set("site_id", fmt.Sprint(siblingID)) }, 400},
			{"foreign origin", func(f url.Values) { f.Set("public_origin", "https://other.example.test") }, 400},
			{"preview target", func(f url.Values) { f.Set("target", "macos/arm64") }, 400},
			{"unsupported target", func(f url.Values) { f.Set("target", "linux/amd64") }, 400},
			{"zero uses", func(f url.Values) { f.Set("max_uses", "0") }, 400},
			{"excessive uses", func(f url.Values) { f.Set("max_uses", "1001") }, 400},
			{"unlisted expiry", func(f url.Values) { f.Set("hours", "10000") }, 400},
			{"stale release", func(f url.Values) { f.Set("release_digest", strings.Repeat("b", 64)) }, 409},
		} {
			t.Run(test.name, func(t *testing.T) {
				f := form()
				test.change(f)
				rec := request("scoped-operator", "POST", base+"/desktop/invitations", f)
				if rec.Code != test.status {
					t.Fatal("invalid creation returned unexpected status", rec.Code, rec.Body.String())
				}
			})
		}
		if count() != initial {
			t.Fatal("invalid form created state")
		}
	})
	t.Run("approved creation commits scope release audit and one-time token", func(t *testing.T) {
		rec := request("scoped-operator", "POST", base+"/desktop/invitations", form())
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Invitation created") || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "strict-origin" {
			t.Fatal("creation result failed", rec.Code, rec.Body.String())
		}
		match := regexp.MustCompile(`id="desktop-invitation-token"[^>]*>([^<]+)</textarea>`).FindStringSubmatch(rec.Body.String())
		if len(match) != 2 || !enrollment.ValidToken(match[1]) {
			t.Fatal("one-time canonical token was not rendered")
		}
		token := match[1]
		metadata, err := h.Desktop.InstallerMetadata(ctx, catalog, token, h.PublicOrigin)
		if err != nil || metadata.TenantID != tenantID || metadata.SiteID != siteID || metadata.ReleaseDigest != release.Digest() || metadata.AvailableUses != 1 || metadata.ExpiresAt.After(release.Manifest().ExpiresAt) {
			t.Fatal("created invitation lost its scope, limit or release binding", err)
		}
		if count() != initial+1 {
			t.Fatal("creation did not publish exactly one invitation")
		}
		digest := sha256.Sum256([]byte(token))
		var audited bool
		if err := h.Model.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_invitations i JOIN uem_agent_audit a ON a.resource_id=i.id WHERE i.token_hash=$1 AND a.action='agent.invitation.create' AND a.actor='scoped-operator' AND a.tenant_id=$2 AND a.site_id=$3)`, hex.EncodeToString(digest[:]), tenantID, siteID).Scan(&audited); err != nil || !audited {
			t.Fatal("creation did not commit the scoped actor audit", err)
		}
		list := request("scoped-operator", "GET", base+"/desktop/enrollment", nil)
		if list.Code != 200 || strings.Contains(list.Body.String(), token) {
			t.Fatal("invitation listing exposed a recoverable token")
		}
		artifact("desktop-created-invitation", rec)
	})
	t.Run("missing configuration signer or changed package prevents creation", func(t *testing.T) {
		before := count()
		h.DesktopBootstrapReady = false
		rec := request("scoped-operator", "POST", base+"/desktop/invitations", form())
		h.DesktopBootstrapReady = true
		if rec.Code != 503 {
			t.Fatal("missing configuration signer accepted invitation", rec.Code)
		}
		content, err := os.ReadFile(packagePath)
		if err != nil {
			t.Fatal(err)
		}
		modified := append([]byte(nil), content...)
		modified[0] ^= 1
		if err := os.WriteFile(packagePath, modified, 0644); err != nil {
			t.Fatal(err)
		}
		rec = request("scoped-operator", "POST", base+"/desktop/invitations", form())
		if err := os.WriteFile(packagePath, content, 0644); err != nil {
			t.Fatal(err)
		}
		if rec.Code != 503 || count() != before {
			t.Fatal("changed package created invitation", rec.Code)
		}
	})
	// The existing identity/invitation revocation tests above use this same
	// scoped registry; creation never consumes an invitation or issues keys.
	var identities int
	if err := h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_agent_identities`).Scan(&identities); err != nil || identities != 3 {
		t.Fatal("invitation creation changed device identities", identities, err)
	}
}
