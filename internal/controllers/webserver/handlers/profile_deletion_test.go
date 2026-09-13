package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/stretchr/testify/require"
)

func TestProfileDeletionAcceptsOnlyTheRouteTarget(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	for _, tc := range []struct {
		name, query, body, contentType string
		invalid                        bool
	}{
		{"HTMX empty", "", "", "", false}, {"empty form header", "", "", "application/x-www-form-urlencoded", false},
		{"query target", "?profile=17", "", "", true}, {"empty query", "?", "", "", true}, {"body target", "", "profile=17", "application/x-www-form-urlencoded", true},
		{"query pagination", "?page=2", "", "", true}, {"query duplicate", "?profile=17&profile=18", "", "", true}, {"body token", "", "csrf=owned", "application/x-www-form-urlencoded", true},
		{"body padding", "", strings.Repeat("&", 8193), "application/x-www-form-urlencoded", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("DELETE", "/profiles/17"+tc.query, strings.NewReader(tc.body)).WithContext(ctx)
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			err := profileDeletionForm(echo.New().NewContext(r, httptest.NewRecorder()))
			require.Equal(t, tc.invalid, err != nil)
		})
	}
}
