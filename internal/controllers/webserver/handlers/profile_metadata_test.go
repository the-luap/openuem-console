package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/stretchr/testify/require"
)

func TestProfileMetadataFormStrictValuesAndBounds(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	valid := "profile-description=Owned+profile&profile-assignment=useTags"
	for _, tc := range []struct {
		name, query, body string
		invalid           bool
	}{
		{"valid", "", valid, false}, {"native CSRF", "", valid + "&csrf=owned", false}, {"list context", "", valid + "&page=2&pageSize=25&sortBy=name&sortOrder=asc", false},
		{"empty", "", "", true}, {"missing mode", "", "profile-description=Owned", true}, {"unknown mode", "", "profile-description=Owned&profile-assignment=all", true},
		{"blank name", "", "profile-description=%20%09&profile-assignment=useTags", true}, {"bad UTF8", "", "profile-description=%FF&profile-assignment=useTags", true},
		{"target override", "", valid + "&profile=17", true}, {"query", "?page=2", valid, true}, {"empty query", "?", valid, true},
		{"duplicate name", "", valid + "&profile-description=Second", true}, {"duplicate mode", "", valid + "&profile-assignment=applyToAll", true}, {"duplicate page", "", valid + "&page=1&page=2", true},
		{"padded", "", valid + strings.Repeat("&", 8193), true}, {"long name", "", "profile-description=" + strings.Repeat("x", 2049) + "&profile-assignment=useTags", true},
		{"malformed", "", valid + "&page=%zz", true}, {"multiline", "", url.Values{"profile-description": {"Owned\n第二行"}, "profile-assignment": {"useTags"}}.Encode(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/profiles/17"+tc.query, strings.NewReader(tc.body)).WithContext(ctx)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			_, err := profileMetadataForm(echo.New().NewContext(r, httptest.NewRecorder()))
			require.Equal(t, tc.invalid, err != nil)
		})
	}
}
