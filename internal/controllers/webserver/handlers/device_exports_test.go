package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/stretchr/testify/require"
)

func TestDeviceExportFormBoundaries(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	for _, name := range []string{"valid", "json", "encoding", "duplicate-content-type", "query", "empty-query", "missing-csrf", "wrong-csrf", "duplicate-csrf", "duplicate-format", "cursor", "oversized", "chunked-oversized", "cached-oversized"} {
		t.Run(name, func(t *testing.T) {
			form := url.Values{"csrf": {"owned-csrf"}, "format": {"json"}, "q": {"Owned"}, "platform": {"windows"}, "sort": {"recent"}}
			if name == "missing-csrf" {
				form.Del("csrf")
			}
			if name == "wrong-csrf" {
				form.Set("csrf", "wrong")
			}
			if name == "duplicate-csrf" {
				form.Add("csrf", "another")
			}
			if name == "duplicate-format" {
				form.Add("format", "csv")
			}
			if name == "cursor" {
				form.Set("after", "owned-position")
			}
			if strings.Contains(name, "oversized") {
				form.Set("q", strings.Repeat("x", 8193))
			}
			target := "/devices/export"
			if name == "query" {
				target += "?q=another"
			}
			if name == "empty-query" {
				target += "?"
			}
			r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode())).WithContext(ctx)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if name == "json" {
				r.Header.Set("Content-Type", "application/json")
			}
			if name == "encoding" {
				r.Header.Set("Content-Encoding", "gzip")
			}
			if name == "duplicate-content-type" {
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			}
			if name == "chunked-oversized" || name == "cached-oversized" {
				r.ContentLength = -1
			}
			if name == "cached-oversized" {
				r.PostForm = form
			}
			c := echo.New().NewContext(r, httptest.NewRecorder())
			c.Set("csrf", "owned-csrf")
			got, err := deviceExportForm(c)
			if name == "valid" {
				require.NoError(t, err)
				require.Equal(t, form, got)
			} else {
				require.Error(t, err)
				require.Nil(t, got)
			}
		})
	}
}
