package mdm_views

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/profiles_views"
	"github.com/stretchr/testify/require"
)

func TestProfileDeletionConfirmation(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	for state, info := range map[string]*partials.CommonInfo{"global": {TenantID: "-1", SiteID: "-1"}, "organization": {TenantID: "1", SiteID: "-1"}, "site": {TenantID: "1", SiteID: "2"}, "long": {TenantID: "1", SiteID: "2"}} {
		review := &inventory.ProfileDeletionReview{ID: 17, Name: "Owned <deletion> profile"}
		if state == "long" {
			review.Name = strings.Repeat("界", 512)
			review.NameTruncated = true
		}
		var body bytes.Buffer
		body.WriteString(`<!doctype html><html class="uk-theme-openuem"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"><script src="/assets/js/htmx.min.js"></script></head><body class="bg-background text-foreground" hx-headers='{"X-CSRF-Token":"owned-csrf"}'><main id="main" class="p-4">`)
		require.NoError(t, profiles_views.ProfileDeletionConfirmation(review, info).Render(ctx, &body))
		body.WriteString(`</main></body></html>`)
		if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
			require.NoError(t, os.MkdirAll(dir, 0755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "profile-deletion-"+state+".html"), body.Bytes(), 0644))
		}
	}
}
