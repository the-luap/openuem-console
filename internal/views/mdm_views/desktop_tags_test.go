package mdm_views

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestDesktopTagHTMXForms(t *testing.T) {
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	var body bytes.Buffer
	body.WriteString(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><script src="/assets/js/htmx.min.js"></script></head><body hx-headers='{"X-CSRF-Token":"owned-csrf"}'><main id="main"><input name="filterByOs" value="windows"><input name="filterByTag7" value="on">`)
	info := &partials.CommonInfo{TenantID: "1", SiteID: "2"}
	p := partials.PaginationAndSort{CurrentPage: 2, PageSize: 25, SortBy: "hostname", SortOrder: "asc"}
	tag := &ent.Tag{ID: 42, Tag: "Owned membership tag", Color: "blue"}
	for i, path := range []string{"/tenant/1/site/2/agents", "/tenant/1/site/2/computers", "/tenant/1/admin/update-agents", "/profiles/17/tags", "/tenant/1/profiles/17/tags", "/tenant/1/site/2/profiles/17/tags"} {
		target := "owned-agent"
		if i >= 3 {
			target = "17"
		}
		fmt.Fprintf(&body, `<section id="tag-action-%d">`, i)
		if i != 2 {
			require.NoError(t, partials.AddTagButton(p, []*ent.Tag{tag}, nil, target, path, "post", "#main", "outerHTML", info).Render(ctx, &body))
		}
		require.NoError(t, partials.ShowAppliedTags([]*ent.Tag{tag}, target, p, path, "#main", "outerHTML").Render(ctx, &body))
		body.WriteString(`</section>`)
	}
	body.WriteString(`</main></body></html>`)
	if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
		require.NoError(t, os.MkdirAll(dir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "desktop-tag-actions.html"), body.Bytes(), 0644))
	}
}
