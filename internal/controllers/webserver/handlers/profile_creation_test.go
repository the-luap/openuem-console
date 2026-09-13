package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/stretchr/testify/require"
)

func TestProfileCreationFormKeepsAssignmentOutOfTheRequest(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	for _, tc := range []struct {
		name, query, body string
		invalid           bool
	}{
		{"valid", "", "profile-description=Owned+profile", false}, {"native token", "", "profile-description=Owned&csrf=owned", false},
		{"blank", "", "profile-description=%20%09", true}, {"missing", "", "", true}, {"duplicate", "", "profile-description=One&profile-description=Two", true},
		{"assignment", "", "profile-description=Owned&profile-assignment=applyToAll", true}, {"identity", "", "profile-description=Owned&profile=17", true}, {"audience", "", "profile-description=Owned&tenant-id=1", true},
		{"query", "?profile-description=Other", "profile-description=Owned", true}, {"empty query", "?", "profile-description=Owned", true}, {"padded", "", "profile-description=Owned" + strings.Repeat("&", 8193), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/profiles/new"+tc.query, strings.NewReader(tc.body)).WithContext(ctx)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			d, err := profileDefinitionForm(echo.New().NewContext(r, httptest.NewRecorder()), true)
			require.Equal(t, tc.invalid, err != nil)
			if err == nil {
				require.Equal(t, "dontApplyToAll", d.Assignment)
			}
		})
	}
}
