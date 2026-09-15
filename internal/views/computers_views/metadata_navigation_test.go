package computers_views

import (
	"bytes"
	"context"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestLegacyMetadataNavigationUsesCurrentEditorWithoutDeletionQuery(t *testing.T) {
	for _, role := range []access.Role{access.Viewer, access.TenantAdmin} {
		for _, confirm := range []bool{false, true} {
			info := &partials.CommonInfo{TenantID: "1", SiteID: "1", Principal: access.Principal{UserID: "actor", Grants: []access.Grant{{Role: role, Scope: access.Scope{TenantID: 1}}}}}
			var out bytes.Buffer
			require.NoError(t, ComputersNavbar("device", "metadata", "", confirm, info, "windows", false, "0.11.0").Render(context.Background(), &out))
			doc, err := goquery.NewDocumentFromReader(&out)
			require.NoError(t, err)
			links := doc.Find(`a[href*="/metadata"]`)
			if role == access.Viewer {
				require.Zero(t, links.Length())
				continue
			}
			require.Equal(t, 1, links.Length())
			require.Equal(t, "/tenant/1/site/1/computers/device/metadata", links.AttrOr("href", ""))
			require.Equal(t, "false", links.AttrOr("hx-boost", ""))
			require.Zero(t, links.Filter("[hx-get]").Length())
		}
	}
}
