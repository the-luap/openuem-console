package desktop_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestDeviceNotesEscapeDraftAndSanitizeSavedMarkdown(t *testing.T) {
	require.NoError(t, locales.Load())
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "notes-admin")
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "1", IsComputer: true, CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Example organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}, Principal: access.Principal{UserID: "notes-admin", Grants: []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}}}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/computers/notes-device/notes", nil).WithContext(ctx), httptest.NewRecorder())
	data := &inventory.DeviceNotes{DeviceID: "notes-device", DeviceName: "Finance laptop", Notes: "**Saved heading**\n\n<script>window.notesOwned=true</script>\n\n[Unsafe](javascript:alert(1))\n\n![Remote image](https://example.invalid/tracker.png)\n\n[Safe link](https://example.test/reference)\n\n" + strings.Repeat("long", 200), Revision: "f531367c-00bc-4f1a-a8ed-6162d9923716"}
	draft := "My draft </textarea><script>window.draftOwned=true</script>"
	var out bytes.Buffer
	require.NoError(t, Notes(c, info, data, draft, "These notes changed. Your draft is preserved; review the current notes before saving.").Render(ctx, &out))
	html := out.String()
	require.Contains(t, html, "<strong>Saved heading</strong>")
	require.Contains(t, html, "My draft &lt;/textarea&gt;&lt;script&gt;")
	require.Contains(t, html, `name="revision" value="`+data.Revision+`"`)
	require.Contains(t, html, `name="csrf"`)
	require.Contains(t, html, `method="post"`)
	require.Contains(t, html, `hx-boost="false"`)
	for _, unsafe := range []string{"<script>window.", "javascript:alert", "tracker.png"} {
		require.NotContains(t, html, unsafe)
	}
	require.Contains(t, html, `href="https://example.test/reference"`)
	dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS")
	if dir == "" {
		dir = os.Getenv("DEVICE_NOTES_TEST_ARTIFACT_DIR")
	}
	if dir != "" {
		require.NoError(t, os.MkdirAll(dir, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "notes-conflict.html"), out.Bytes(), 0600))
	}
}
