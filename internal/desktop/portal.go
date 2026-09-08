package desktop

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-console/internal/desktop/protocol"
)

//go:embed portal.html
var portalHTML string

//go:embed portal.css
var portalCSS string

var portalTemplate = template.Must(template.New("desktop-enrollment").Parse(portalHTML))

type portalData struct {
	CSS                         template.CSS
	Origin, Organization, Site  string
	Target, Release, Expires    string
	TenantID, SiteID, Remaining int
	PackageURL, InvitationURL   string
	ConfigurationURL            string
	Available, Compatible       bool
	Mac                         bool
}

func (h *PublicHandler) portal(w http.ResponseWriter, r *http.Request, route protocol.Route) {
	data := portalData{CSS: template.CSS(portalCSS), Origin: h.origin}
	metadata, err := h.store.InstallerMetadata(r.Context(), h.catalog, route.Token, h.origin)
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, registry.ErrNotFound) || errors.Is(err, ErrNoRelease) || errors.Is(err, ErrWithdrawn) || errors.Is(err, artifacts.ErrExpired) {
			status = http.StatusNotFound
		}
		h.portalPage(w, r, status, data)
		return
	}
	// The registry read verifies the current release transactionally; verify its
	// retained envelope again to obtain public version/target metadata without
	// trusting unsigned labels. A later claim still rechecks withdrawal/expiry.
	release, err := artifacts.Verify(metadata.ReleaseEnvelope, h.catalog.trusted, time.Now(), artifacts.Checkpoint{})
	if err != nil || release.Digest() != metadata.ReleaseDigest {
		h.portalPage(w, r, http.StatusServiceUnavailable, data)
		return
	}
	data.Available = true
	data.Compatible = len(h.bootstrapKey) != 0 && metadata.Artifact.AgentSize > 0 && metadata.Artifact.AgentSHA256 != ""
	if data.Compatible {
		// A changed site label can invalidate signed bootstrap syntax even when
		// the release remains approved. Offer files only if the same metadata can
		// produce the configuration that the native client will verify.
		configuration, err := h.signConfiguration(metadata, route.Token, time.Now().UTC())
		clear(configuration)
		data.Compatible = err == nil
	}
	data.Organization, data.Site = metadata.Organization, metadata.Site
	data.TenantID, data.SiteID, data.Remaining = metadata.TenantID, metadata.SiteID, metadata.AvailableUses
	data.Release, data.Expires = release.Manifest().Version, metadata.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC")
	data.Target = "Windows (x64)"
	if metadata.Platform == "macos" {
		data.Mac = true
		data.Target = "Mac (Intel)"
		if metadata.Architecture == "arm64" {
			data.Target = "Mac (Apple silicon)"
		}
	} else if metadata.Architecture == "arm64" {
		data.Target = "Windows (ARM64)"
	}
	base := "/enroll/desktop/" + route.Token
	data.PackageURL = protocol.DownloadPath(metadata.ReleaseDigest, metadata.Platform, metadata.Architecture)
	data.InvitationURL, data.ConfigurationURL = base+"/invitation", base+"/configuration"
	if route.Kind == "invitation" {
		if !data.Compatible {
			http.NotFound(w, r)
			return
		}
		// This is the existing limited bearer token, never an issued device key.
		// Download scanners cannot reserve a use or create/activate an identity.
		content := route.Token + "\n"
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="openuem-invitation.txt"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(content))
		}
		return
	}
	h.portalPage(w, r, http.StatusOK, data)
}

// Bound rendering before writing headers so malformed/oversized stored labels
// cannot produce a partial successful page or an unbounded HTTP response.
type portalBuffer struct{ buffer bytes.Buffer }

func (b *portalBuffer) Len() int      { return b.buffer.Len() }
func (b *portalBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *portalBuffer) Write(data []byte) (int, error) {
	if len(data) > (64<<10)-b.Len() {
		return 0, errors.New("enrollment page is too large")
	}
	return b.buffer.Write(data)
}

func (h *PublicHandler) portalPage(w http.ResponseWriter, r *http.Request, status int, data portalData) {
	var output portalBuffer
	if err := portalTemplate.Execute(&output, data); err != nil {
		http.Error(w, "enrollment instructions are unavailable", http.StatusServiceUnavailable)
		return
	}
	digest := sha256.Sum256([]byte(portalCSS))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'sha256-"+base64.StdEncoding.EncodeToString(digest[:])+"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(output.Len()))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(output.Bytes())
	}
}
