package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestAppleUpdateFormBoundary(t *testing.T) {
	for _, name := range []string{"apply", "remove", "missing-policy", "duplicate-policy", "invalid-policy", "uppercase-policy", "duplicate-release", "duplicate-deadline", "duplicate-remove", "duplicate-csrf", "missing-release", "missing-build", "extra-build", "missing-deadline", "mixed-action", "false-remove", "unknown", "missing-csrf", "wrong-csrf", "header-only", "query", "empty-query", "json", "encoding", "duplicate-content-type", "oversized", "chunked-oversized", "parsed-oversized", "malformed"} {
		t.Run(name, func(t *testing.T) {
			f := url.Values{"csrf": {"owned-csrf"}, "expected_policy": {strings.Repeat("a", 64)}, "target_release": {"18.7.1/22H100"}, "deadline": {"2026-10-01T18:00"}, "details_url": {"https://example.test/update"}}
			switch name {
			case "remove":
				f = url.Values{"csrf": {"owned-csrf"}, "expected_policy": {strings.Repeat("a", 64)}, "remove": {"true"}}
			case "missing-policy":
				f.Del("expected_policy")
			case "duplicate-policy":
				f.Add("expected_policy", strings.Repeat("a", 64))
			case "invalid-policy":
				f.Set("expected_policy", strings.Repeat("g", 64))
			case "uppercase-policy":
				f.Set("expected_policy", strings.Repeat("A", 64))
			case "duplicate-release":
				f.Add("target_release", "18.8/22I100")
			case "duplicate-deadline":
				f.Add("deadline", "2026-11-01T18:00")
			case "duplicate-remove":
				f = url.Values{"csrf": {"owned-csrf"}, "expected_policy": {strings.Repeat("a", 64)}, "remove": {"true", "true"}}
			case "duplicate-csrf":
				f.Add("csrf", "owned-csrf")
			case "missing-release":
				f.Del("target_release")
			case "missing-build":
				f.Set("target_release", "18.7.1/")
			case "extra-build":
				f.Set("target_release", "18.7.1/22H100/extra")
			case "missing-deadline":
				f.Del("deadline")
			case "mixed-action":
				f.Set("remove", "true")
			case "false-remove":
				f = url.Values{"csrf": {"owned-csrf"}, "expected_policy": {strings.Repeat("a", 64)}, "remove": {"false"}}
			case "unknown":
				f.Set("tenant_id", "2")
			case "missing-csrf", "header-only":
				f.Del("csrf")
			case "wrong-csrf":
				f.Set("csrf", "wrong")
			}
			if strings.Contains(name, "oversized") {
				f.Set("details_url", strings.Repeat("x", 8193))
			}
			path := "/ios/10000000-0000-4000-8000-000000000001/update"
			if name == "query" {
				path += "?remove=true"
			}
			if name == "empty-query" {
				path += "?"
			}
			body := f.Encode()
			if name == "malformed" {
				body += "&deadline=%zz"
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
			case "header-only":
				r.Header.Set("X-CSRF-Token", "owned-csrf")
			case "chunked-oversized":
				r.ContentLength = -1
			case "parsed-oversized":
				r.ContentLength = -1
				r.PostForm = f
			}
			c := echo.New().NewContext(r, httptest.NewRecorder())
			c.Set("csrf", "owned-csrf")
			p, err := appleUpdateForm(c)
			if name == "apply" {
				require.NoError(t, err)
				require.Equal(t, "18.7.1", p.policy.TargetVersion)
				require.Equal(t, "22H100", p.policy.TargetBuild)
				require.Equal(t, "2026-10-01T18:00:00", p.policy.Deadline)
			} else if name == "remove" {
				require.NoError(t, err)
				require.Equal(t, strings.Repeat("a", 64), p.expectedPolicy)
				require.Nil(t, p.policy)
			} else {
				require.Error(t, err)
				require.Nil(t, p)
			}
		})
	}
}
