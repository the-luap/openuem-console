package mdm_views

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/tagcolor"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestSharedTagColorCompatibility(t *testing.T) {
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	colors := append(tagcolor.Names(), "#AbC123", "#ffffff", "#000000", "red;background:url(https://outside.example.test)")
	var tags []*ent.Tag
	for i, color := range colors {
		tags = append(tags, &ent.Tag{ID: i + 1, Tag: color, Color: color, Description: "Owned compatibility tag"})
	}
	tags[len(tags)-1].Tag = strings.Repeat("Long", 60) + "<script>"
	var body bytes.Buffer
	body.WriteString(`<!doctype html><html class="dark"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"></head><body class="bg-background text-foreground"><main id="tag-color-fixture" class="p-4"><h1>Tag color compatibility</h1><section id="read-only-tags">`)
	require.NoError(t, partials.ShowAppliedTagsWithoutRemoveOption(tags).Render(ctx, &body))
	body.WriteString(`</section><section id="removable-tags" class="flex flex-wrap gap-2 mt-4">`)
	p := partials.PaginationAndSort{CurrentPage: 1, PageSize: 25}
	require.NoError(t, partials.ShowAppliedTags(tags, "owned-agent", p, "/tenant/1/site/1/computers", "#main", "outerHTML").Render(ctx, &body))
	body.WriteString(`</section><section id="available-tags" class="mt-4">`)
	require.NoError(t, partials.AddTagButton(p, tags, nil, "owned-agent", "/tenant/1/site/1/computers", "post", "#main", "outerHTML", &partials.CommonInfo{TenantID: "1", SiteID: "1"}).Render(ctx, &body))
	body.WriteString(`</section></main></body></html>`)
	html := body.String()
	require.NotContains(t, html, "outside.example.test")
	require.NotContains(t, html, "<script>")
	require.Contains(t, html, "background-color:#abc123;")
	if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
		require.NoError(t, os.MkdirAll(dir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "tag-color-compatibility.html"), body.Bytes(), 0644))
	}
}
