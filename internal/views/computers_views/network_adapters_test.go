package computers_views_test

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
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/computers_views"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"golang.org/x/net/html"
)

func TestNetworkAdapterReportsRenderLiteralDNS(t *testing.T) {
	if err := locales.Load(); err != nil {
		t.Fatal(err)
	}
	ctx, err := locales.WithLocale(context.Background(), "en")
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	sm.Put(ctx, "uid", "owned-network-admin")
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "1", IsComputer: true,
		CurrentVersion: "0.11.0", LatestVersion: "0.11.0", EndpointInboundDisabled: true,
		Principal: access.Principal{UserID: "owned-network-admin", Grants: []access.Grant{{Role: access.Administrator}}},
		Tenants:   []*ent.Tenant{{ID: 1, Description: "Example organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1/computers/owned-network/network-adapters", nil).WithContext(ctx), httptest.NewRecorder())
	// Version zero avoids unrelated live status polling from this read-only page.
	agent := &ent.Agent{ID: "owned-network", Nickname: "Network fixture", Os: "windows", AgentStatus: "Enabled", Edges: ent.AgentEdges{Release: &ent.Release{Version: "0.0.0"}}}
	for _, state := range []string{"ordinary", "injected", "long", "empty"} {
		adapters := []*ent.NetworkAdapter{{Name: "Owned Ethernet", MACAddress: "02:00:00:00:00:01", Addresses: "192.0.2.10", Subnet: "255.255.255.0", DefaultGateway: "192.0.2.1", DhcpEnabled: true, DNSServers: "192.0.2.53, 2001:db8::53", DNSDomain: "owned.example.test", Speed: "1 Gbps"}}
		switch state {
		case "injected":
			adapters[0].DNSServers = `192.0.2.53<img src="data:," data-owned-dns="server" onerror="window.__ownedDNSMarkup=true">`
			adapters[0].DNSDomain = `owned.example.test<img src="data:," data-owned-dns="domain" onerror="window.__ownedDNSMarkup=true">`
		case "long":
			adapters[0].DNSServers = strings.Repeat("2001:db8:1234:5678::53, ", 35)
			adapters[0].DNSDomain = strings.Repeat("owned-domain-", 30) + ".example.test"
		case "empty":
			adapters = nil
		}
		var body bytes.Buffer
		pagination := partials.NewPaginationAndSort(5)
		pagination.NItems = len(adapters)
		component := computers_views.NetworkAdapters(c, pagination, agent, adapters, false, 5, info, false, true)
		if err := computers_views.InventoryIndex("Network adapters", component, info).Render(ctx, &body); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(body.String(), `<img src="data:,"`) {
			t.Fatal("reported DNS values became HTML during template rendering")
		}
		document, err := html.Parse(bytes.NewReader(body.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		var text strings.Builder
		var visit func(*html.Node)
		visit = func(node *html.Node) {
			if node.Type == html.TextNode {
				text.WriteString(node.Data)
			}
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				visit(child)
			}
		}
		visit(document)
		for _, adapter := range adapters {
			if !strings.Contains(text.String(), adapter.DNSServers) || !strings.Contains(text.String(), adapter.DNSDomain) {
				t.Fatal("reported DNS values were not readable as literal page text", state)
			}
		}
		if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "desktop-network-"+state+".html"), body.Bytes(), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
}
