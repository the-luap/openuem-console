package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/stretchr/testify/require"
)

func TestProfileStatusFormBoundsRouteOnlyActions(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	for _, tc := range []struct {
		name, query, body string
		invalid           bool
	}{
		{"legacy empty", "", "", false},
		{"list context", "", "page=2&pageSize=25&sortBy=name&sortOrder=asc", false},
		{"native token", "", "csrf=owned-token", false},
		{"query", "?page=2", "", true},
		{"empty query", "?", "", true},
		{"target override", "", "profile=17", true},
		{"status override", "", "enabled=true", true},
		{"duplicate", "", "page=2&page=3", true},
		{"malformed", "", "page=%zz", true},
		{"padded", "", strings.Repeat("&", 8193), true},
		{"long field", "", "sortBy=" + strings.Repeat("x", 129), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/profiles/17/enable"+tc.query, strings.NewReader(tc.body)).WithContext(ctx)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			err := profileStatusForm(echo.New().NewContext(r, httptest.NewRecorder()))
			require.Equal(t, tc.invalid, err != nil)
		})
	}
}
