package admin_views

import (
	"bytes"
	"context"
	"fmt"
	"github.com/open-uem/openuem-console/internal/security/access"
	"io"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/assert"
)

var globalNavbarTests = []string{"users", "sessions", "smtp", "sessions", "settings", "update-servers", "certificates"}

var tenantNavbarTests = []string{"tags", "metadata", "settings", "update-agents"}

func TestTenantConfigNavbarTabs(t *testing.T) {
	config := partials.CommonInfo{TenantID: "1", SiteID: "-1", Principal: access.Principal{UserID: "admin", Grants: []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}}}
	for _, test := range tenantNavbarTests {
		t.Run(test, func(t *testing.T) {
			// Pipe the rendered template into goquery.
			r, w := io.Pipe()
			go func() {
				_ = ConfigNavbar(test, true, true, &config).Render(context.Background(), w)
				_ = w.Close()
			}()
			doc, err := goquery.NewDocumentFromReader(r)
			if err != nil {
				t.Fatalf("failed to read template: %v", err)
			}

			selection := doc.Find(".uk-active")
			assert.Equal(t, 1, selection.Length(), "should get only one active tab")
			val, exists := selection.Find("a").Attr("href")
			assert.Equal(t, true, exists, "should get href")
			assert.Equal(t, fmt.Sprintf("/tenant/%s/admin/%s", config.TenantID, test), val, "should get active tab")
		})
	}
}

func TestGlobalConfigNavbarTabs(t *testing.T) {
	config := partials.CommonInfo{TenantID: "-1"}
	for _, test := range globalNavbarTests {
		t.Run(test, func(t *testing.T) {
			// Pipe the rendered template into goquery.
			r, w := io.Pipe()
			go func() {
				_ = ConfigNavbar(test, true, true, &config).Render(context.Background(), w)
				_ = w.Close()
			}()
			doc, err := goquery.NewDocumentFromReader(r)
			if err != nil {
				t.Fatalf("failed to read template: %v", err)
			}

			selection := doc.Find(".uk-active")
			assert.Equal(t, 1, selection.Length(), "should get only one active tab")
			val, exists := selection.Find("a").Attr("href")
			assert.Equal(t, true, exists, "should get href")
			assert.Equal(t, fmt.Sprintf("/admin/%s", test), val, "should get active tab")
		})
	}
}

func TestMetadataNavbarUsesCurrentCapabilityAndNativeNavigation(t *testing.T) {
	for _, role := range []access.Role{access.Viewer, access.Operator, access.TenantAdmin, access.Administrator} {
		scope := access.Scope{TenantID: 1}
		if role == access.Administrator {
			scope = access.Scope{}
		}
		info := &partials.CommonInfo{TenantID: "1", SiteID: "-1", Principal: access.Principal{UserID: "actor", Grants: []access.Grant{{Role: role, Scope: scope}}}}
		var out bytes.Buffer
		assert.NoError(t, ConfigNavbar("metadata", true, true, info).Render(context.Background(), &out))
		doc, err := goquery.NewDocumentFromReader(&out)
		assert.NoError(t, err)
		link := doc.Find(`a[href="/tenant/1/admin/metadata"]`)
		expected := 0
		if role == access.TenantAdmin || role == access.Administrator {
			expected = 1
		}
		assert.Equal(t, expected, link.Length())
		assert.Zero(t, link.Filter("[hx-get]").Length())
	}
}
