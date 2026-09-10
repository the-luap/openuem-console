// Package protocol defines the exact public desktop enrollment route allowlist.
package protocol

import (
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/open-uem/nats/enrollment"
)

const DownloadTimeout = 15 * time.Minute

type Route struct {
	Kind, Token, Digest, Platform, Architecture, DeviceID string
}

// Parse never normalizes a path or accepts query parameters. The gateway and
// private enrollment listener use the same allowlist, including HTTP methods.
func Parse(r *http.Request) (Route, bool) {
	if r.URL == nil || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Opaque != "" || r.URL.Fragment != "" {
		return Route{}, false
	}
	p := strings.Split(r.URL.Path, "/")
	if len(p) < 4 || p[0] != "" || p[1] != "enroll" || p[2] != "desktop" {
		return Route{}, false
	}
	read := r.Method == http.MethodGet || r.Method == http.MethodHead
	if len(p) == 7 && p[3] == "identities" && enrollment.ValidDeviceID(p[4]) && p[5] == "renewal" && (p[6] == "prepare" || p[6] == "confirm" || p[6] == "resolve") && r.Method == http.MethodPost {
		return Route{Kind: "renewal-" + p[6], DeviceID: p[4]}, true
	}
	if len(p) == 4 && p[3] == "bootstrap-keys" && read {
		return Route{Kind: "bootstrap-keys"}, true
	}
	if len(p) == 4 && enrollment.ValidToken(p[3]) && read {
		return Route{Kind: "portal", Token: p[3]}, true
	}
	if len(p) == 5 && enrollment.ValidToken(p[3]) {
		if ((p[4] == "metadata" || p[4] == "configuration" || p[4] == "invitation") && read) || (p[4] == "claim" && r.Method == http.MethodPost) {
			return Route{Kind: p[4], Token: p[3]}, true
		}
	}
	if len(p) == 7 && p[3] == "releases" && read && (p[5] == "windows" || p[5] == "macos") && (p[6] == "amd64" || p[6] == "arm64") {
		digest, err := hex.DecodeString(p[4])
		if err == nil && len(digest) == 32 && hex.EncodeToString(digest) == p[4] {
			return Route{Kind: "download", Digest: p[4], Platform: p[5], Architecture: p[6]}, true
		}
	}
	return Route{}, false
}

func DownloadPath(digest, platform, architecture string) string {
	return "/enroll/desktop/releases/" + digest + "/" + platform + "/" + architecture
}
