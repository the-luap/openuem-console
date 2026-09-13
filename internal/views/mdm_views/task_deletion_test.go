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

func TestTaskDeletionConfirmation(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	for state, info := range map[string]*partials.CommonInfo{"global": {TenantID: "-1", SiteID: "-1"}, "organization": {TenantID: "1", SiteID: "-1"}, "site": {TenantID: "1", SiteID: "2"}, "long": {TenantID: "1", SiteID: "2"}} {
		review := &inventory.TaskDeletionReview{ID: 101, ProfileID: 17, Name: "Owned <deletion> task"}
		if state == "long" {
			review.Name = strings.Repeat("界", 512)
			review.NameTruncated = true
		}
		var body bytes.Buffer
		body.WriteString(`<!doctype html><html class="uk-theme-openuem"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"><script src="/assets/js/htmx.min.js"></script></head><body class="bg-background text-foreground" hx-headers='{"X-CSRF-Token":"owned-csrf"}'><main id="main" class="p-4">`)
		require.NoError(t, profiles_views.TaskDeletionConfirmation(review, info).Render(ctx, &body))
		require.NotContains(t, body.String(), "MISSING")
		body.WriteString(`</main></body></html>`)
		if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
			require.NoError(t, os.MkdirAll(dir, 0755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "task-deletion-"+state+".html"), body.Bytes(), 0644))
		}
	}
}
