package desktop_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/a-h/templ"
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

func TestCustomMetadataNativeFormsAndDeletionStates(t *testing.T) {
	require.NoError(t, locales.Load())
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "metadata-admin")
	for _, state := range []string{"fields", "fields-empty", "device", "device-empty", "definition-new", "definition", "definition-conflict", "value", "value-empty", "value-conflict", "long", "deletion", "deletion-completed", "deletion-expired", "deletion-conflict"} {
		t.Run(state, func(t *testing.T) {
			info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "1", IsComputer: true, CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Example organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}, Principal: access.Principal{UserID: "metadata-admin", Grants: []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}}}
			c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/computers/metadata-device/metadata", nil).WithContext(ctx), httptest.NewRecorder())
			field := inventory.MetadataField{ID: 7, TenantID: 1, Name: `Owner's field <script>window.metadataOwned=true</script>`, Description: "Current help text\nSecond line", Revision: "350542db-5a9f-4a88-97cb-4b70d5f164d1", Configured: true}
			device := inventory.MetadataDevice{ID: "metadata-device", Name: "Finance laptop", TenantID: 1, SiteID: 1}
			value := &inventory.MetadataValue{Device: device, Field: field, Revision: "be421cab-8cc3-4a29-be3b-da1661e36aa2", Value: "Current <script>window.metadataOwned=true</script>\nSecond line", Present: true}
			var component templ.Component
			switch {
			case strings.HasPrefix(state, "fields"):
				info.SiteID = "-1"
				page := &inventory.MetadataFieldPage{Fields: []inventory.MetadataField{field}, Next: 7}
				if state == "fields-empty" {
					page = &inventory.MetadataFieldPage{}
				}
				component = MetadataFields(c, info, page, "literal %_", 1)
			case strings.HasPrefix(state, "device"):
				page := &inventory.DeviceMetadataPage{Device: device, MetadataFieldPage: inventory.MetadataFieldPage{Fields: []inventory.MetadataField{field}, Next: 7}}
				if state == "device-empty" {
					page.Fields = nil
					page.Next = 0
				}
				component = DeviceMetadata(c, info, page, "literal %_", 1)
			case strings.HasPrefix(state, "definition"):
				info.SiteID = "-1"
				draft, message := field, ""
				if state == "definition-new" {
					field = inventory.MetadataField{TenantID: 1}
					draft = field
				}
				if state == "definition-conflict" {
					draft.Name = "Draft </textarea><script>window.draftOwned=true</script>"
					draft.Description = "Draft help\nPreserved second line"
					message = "Your draft is preserved. Compare it with the currently saved definition."
				}
				component = MetadataField(c, info, &field, draft, message)
			case strings.HasPrefix(state, "deletion"):
				info.SiteID = "-1"
				r := &inventory.MetadataDeletion{ID: "483690a2-f9da-41e8-b9c4-109c642b52de", Actor: "metadata-admin", Field: field, ValueCount: 17, CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(9 * time.Minute)}
				message := ""
				switch state {
				case "deletion-completed":
					at := time.Now()
					r.CompletedAt = &at
				case "deletion-expired":
					r.ExpiresAt = time.Now().Add(-time.Minute)
				case "deletion-conflict":
					message = "The field or its affected values changed. Nothing was deleted."
				}
				component = MetadataDeletion(c, info, r, message)
			default:
				draft, message := value.Value, ""
				if state == "value-empty" {
					value.Value = ""
					value.Present = false
					draft = ""
				}
				if state == "value-conflict" || state == "long" {
					draft = "Draft </textarea><script>window.draftOwned=true</script>\nPreserved second line"
					message = "Your draft is preserved. Compare it with the currently saved data."
				}
				if state == "long" {
					value.Device.Name = strings.Repeat("host", 128)
					value.Field.Name = strings.Repeat("n", 255)
					value.Field.Description = strings.Repeat("long", 1024)
					value.Value = strings.Repeat("value", 3276)
				}
				component = MetadataValue(c, info, value, draft, message)
			}
			var out bytes.Buffer
			require.NoError(t, component.Render(ctx, &out))
			html := out.String()
			require.NotContains(t, html, "<script>window.")
			require.NotContains(t, html, `set #edit-orgmetadata`)
			if state == "deletion-completed" || state == "deletion-expired" || state == "deletion-conflict" {
				require.NotContains(t, html, `name="confirm"`)
			}
			if strings.HasSuffix(state, "conflict") && state != "deletion-conflict" {
				require.Contains(t, html, "Draft &lt;/textarea&gt;")
			}
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0700))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "custom-metadata-"+state+".html"), out.Bytes(), 0600))
			}
		})
	}
}
