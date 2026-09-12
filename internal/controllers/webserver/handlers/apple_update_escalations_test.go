package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestAppleUpdateEscalationFormBoundary(t *testing.T) {
	for _, ack := range []bool{false, true} {
		for _, state := range []string{"valid", "newlines", "unconfirmed", "duplicate-confirmation", "duplicate-revision", "duplicate-key", "duplicate-csrf", "duplicate-intent", "unknown", "wrong-action-field", "missing-revision", "signed-revision", "padded-revision", "negative-revision", "overflow-revision", "invalid-enabled", "missing-csrf", "wrong-csrf", "header-only", "query", "empty-query", "json", "encoding", "duplicate-content-type", "oversized", "chunked-oversized", "parsed-oversized", "malformed"} {
			name := state
			if ack {
				name = "ack/" + name
			}
			t.Run(name, func(t *testing.T) {
				f := url.Values{"csrf": {"owned-csrf"}, "request_key": {"70000000-0000-4000-8000-000000000001"}, "configuration_revision": {"1"}, "confirmed": {"yes"}, "enabled": {"yes"}}
				if ack {
					f.Del("enabled")
					f.Set("incident", "60000000-0000-4000-8000-000000000001")
					f.Set("reason", "Owned coordination")
				}
				valid := state == "valid" || state == "newlines" || (state == "invalid-enabled" && ack)
				switch state {
				case "newlines":
					if ack {
						f.Set("reason", " Owned first line\r\nsecond line ")
					}
				case "unconfirmed":
					f.Del("confirmed")
				case "duplicate-confirmation":
					f.Add("confirmed", "yes")
				case "duplicate-revision":
					f.Add("configuration_revision", "1")
				case "duplicate-key":
					f.Add("request_key", f.Get("request_key"))
				case "duplicate-csrf":
					f.Add("csrf", "owned-csrf")
				case "duplicate-intent":
					if ack {
						f.Add("reason", "duplicate")
					} else {
						f.Add("enabled", "yes")
					}
				case "unknown":
					f.Set("site_id", "2")
				case "wrong-action-field":
					if ack {
						f.Set("enabled", "")
					} else {
						f.Set("incident", "")
					}
				case "missing-revision":
					f.Del("configuration_revision")
				case "signed-revision":
					f.Set("configuration_revision", "+1")
				case "padded-revision":
					f.Set("configuration_revision", "01")
				case "negative-revision":
					f.Set("configuration_revision", "-1")
				case "overflow-revision":
					f.Set("configuration_revision", "2147483647")
				case "invalid-enabled":
					if !ack {
						f.Set("enabled", "true")
					}
				case "missing-csrf", "header-only":
					f.Del("csrf")
				case "wrong-csrf":
					f.Set("csrf", "wrong")
				}
				if strings.Contains(state, "oversized") {
					f.Set("request_key", strings.Repeat("x", 8193))
				}
				path := "/ios/update-plans/30000000-0000-4000-8000-000000000001/group-assignments/40000000-0000-4000-8000-000000000001/escalation"
				if ack {
					path += "/acknowledge"
				}
				if state == "query" {
					path += "?enabled=no"
				}
				if state == "empty-query" {
					path += "?"
				}
				body := f.Encode()
				if state == "malformed" {
					body += "&request_key=%zz"
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
				c.SetParamNames("plan", "assignment")
				c.SetParamValues("30000000-0000-4000-8000-000000000001", "40000000-0000-4000-8000-000000000001")
				parsed, err := appleUpdateEscalationForm(c, ack)
				if valid {
					require.NoError(t, err)
					require.Equal(t, 1, parsed.ConfigurationRevision)
					if state == "newlines" && ack {
						require.Equal(t, "Owned first line\nsecond line", parsed.Reason)
					}
				} else {
					require.Error(t, err)
				}
			})
		}
	}
}
