package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestAppleUpdateExceptionFormBoundary(t *testing.T) {
	for _, state := range []string{"pause", "resume", "newlines", "unconfirmed", "duplicate-confirmation", "duplicate-kind", "duplicate-reason", "duplicate-expiry", "duplicate-token", "duplicate-key", "duplicate-csrf", "unknown", "missing-expiry", "invalid-date", "seconds", "offset", "resume-expiry", "resume-empty-expiry", "unknown-kind", "missing-csrf", "wrong-csrf", "header-only", "query", "empty-query", "json", "encoding", "duplicate-content-type", "oversized", "chunked-oversized", "parsed-oversized", "malformed"} {
		t.Run(state, func(t *testing.T) {
			f := url.Values{"csrf": {"owned-csrf"}, "request_key": {"70000000-0000-4000-8000-000000000001"}, "review_token": {strings.Repeat("a", 64)}, "kind": {"pause"}, "reason": {"Owned maintenance"}, "expires_at": {"2026-10-01T18:00"}, "confirmed": {"yes"}}
			switch state {
			case "resume":
				f.Set("kind", "resume")
				f.Del("expires_at")
			case "newlines":
				f.Set("reason", " Owned first line\r\nsecond line ")
			case "unconfirmed":
				f.Del("confirmed")
			case "duplicate-confirmation":
				f.Add("confirmed", "yes")
			case "duplicate-kind":
				f.Add("kind", "pause")
			case "duplicate-reason":
				f.Add("reason", "Owned reason")
			case "duplicate-expiry":
				f.Add("expires_at", "2026-10-01T18:00")
			case "duplicate-token":
				f.Add("review_token", strings.Repeat("a", 64))
			case "duplicate-key":
				f.Add("request_key", f.Get("request_key"))
			case "duplicate-csrf":
				f.Add("csrf", "owned-csrf")
			case "unknown":
				f.Set("site_id", "2")
			case "missing-expiry":
				f.Del("expires_at")
			case "invalid-date":
				f.Set("expires_at", "2026-02-30T18:00")
			case "seconds":
				f.Set("expires_at", "2026-10-01T18:00:00")
			case "offset":
				f.Set("expires_at", "2026-10-01T18:00Z")
			case "resume-expiry":
				f.Set("kind", "resume")
			case "resume-empty-expiry":
				f.Set("kind", "resume")
				f.Set("expires_at", "")
			case "unknown-kind":
				f.Set("kind", "restore")
			case "missing-csrf", "header-only":
				f.Del("csrf")
			case "wrong-csrf":
				f.Set("csrf", "wrong")
			}
			if strings.Contains(state, "oversized") {
				f.Set("reason", strings.Repeat("x", 8193))
			}
			path := "/ios/10000000-0000-4000-8000-000000000001/update-exceptions"
			if state == "query" {
				path += "?kind=resume"
			}
			if state == "empty-query" {
				path += "?"
			}
			body := f.Encode()
			if state == "malformed" {
				body += "&reason=%zz"
			}
			r := httptest.NewRequest("POST", path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			switch state {
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
			c.SetParamNames("id")
			c.SetParamValues("10000000-0000-4000-8000-000000000001")
			parsed, err := appleUpdateExceptionForm(c)
			if state == "pause" || state == "resume" || state == "newlines" {
				require.NoError(t, err)
				require.Equal(t, f.Get("kind"), parsed.Kind)
				require.Equal(t, f.Get("request_key"), parsed.RequestKey)
				require.Equal(t, f.Get("review_token"), parsed.ReviewToken)
				if state == "resume" {
					require.Nil(t, parsed.ExpiresAt)
				} else {
					require.Equal(t, "2026-10-01T18:00:00Z", parsed.ExpiresAt.Format(time.RFC3339))
				}
				if state == "newlines" {
					require.Equal(t, "Owned first line\nsecond line", parsed.Reason)
				}
			} else {
				require.Error(t, err)
			}
		})
	}
}
