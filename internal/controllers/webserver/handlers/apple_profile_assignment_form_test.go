package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestAppleProfileAssignmentFormBoundary(t *testing.T) {
	for _, name := range []string{"valid", "thousand", "too-many", "duplicate-device", "missing-device", "noncanonical-device", "missing-revision", "duplicate-revision", "noncanonical-revision", "unknown", "duplicate-desired", "missing-csrf", "wrong-csrf", "duplicate-csrf", "header-only-csrf", "query", "empty-query", "json", "encoding", "duplicate-content-type", "oversized", "chunked-oversized", "parsed-oversized", "malformed"} {
		t.Run(name, func(t *testing.T) {
			f := url.Values{"csrf": {"owned-csrf"}, "expected_revision": {"2"}, "desired": {"installed"}, "device_id": {"10000000-0000-4000-8000-000000000001"}}
			switch name {
			case "thousand", "too-many":
				f.Del("device_id")
				count := 1000
				if name == "too-many" {
					count++
				}
				for i := range count {
					f.Add("device_id", fmt.Sprintf("10000000-0000-4000-8000-%012d", i))
				}
			case "duplicate-device":
				f.Add("device_id", f.Get("device_id"))
			case "missing-device":
				f.Del("device_id")
			case "noncanonical-device":
				f.Set("device_id", "00000000-0000-0000-0000-000000000000")
			case "missing-revision":
				f.Del("expected_revision")
			case "duplicate-revision":
				f.Add("expected_revision", "3")
			case "noncanonical-revision":
				f.Set("expected_revision", "02")
			case "unknown":
				f.Set("profile_id", "another-profile")
			case "duplicate-desired":
				f.Add("desired", "removed")
			case "missing-csrf", "header-only-csrf":
				f.Del("csrf")
			case "wrong-csrf":
				f.Set("csrf", "another-csrf")
			case "duplicate-csrf":
				f.Add("csrf", "owned-csrf")
			}
			if strings.Contains(name, "oversized") {
				f.Set("expected_revision", strings.Repeat("1", 65537))
			}
			path := "/ios/configurations/owned/assign"
			if name == "query" {
				path += "?desired=removed"
			} else if name == "empty-query" {
				path += "?"
			}
			body := f.Encode()
			if name == "malformed" {
				body += "&device_id=%zz"
			}
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			switch name {
			case "json":
				r.Header.Set("Content-Type", "application/json")
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
			case "duplicate-content-type":
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			case "header-only-csrf":
				r.Header.Set("X-CSRF-Token", "owned-csrf")
			case "chunked-oversized":
				r.ContentLength = -1
			case "parsed-oversized":
				r.ContentLength = -1
				r.PostForm = f
			}
			c := echo.New().NewContext(r, httptest.NewRecorder())
			c.Set("csrf", "owned-csrf")
			revision, ids, desired, err := appleProfileAssignmentForm(c)
			if name == "valid" || name == "thousand" {
				require.NoError(t, err)
				require.Equal(t, 2, revision)
				require.Equal(t, f["device_id"], ids)
				require.Equal(t, "installed", desired)
			} else {
				require.Error(t, err)
				require.Nil(t, ids)
			}
		})
	}
}
