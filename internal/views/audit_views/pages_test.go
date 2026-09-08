package audit_views

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/invopop/ctxi18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"golang.org/x/net/html"
)

func TestAuditFiltersRenderOnlyTheSelectedOption(t *testing.T) {
	if err := ctxi18n.LoadWithDefault(locales.Content, "en"); err != nil {
		t.Fatal(err)
	}
	ctx, err := ctxi18n.WithLocale(t.Context(), "en")
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	info := &partials.CommonInfo{SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "-1", CSRFToken: "test-token", Principal: access.Principal{UserID: "admin", Grants: []access.Grant{{Role: access.Administrator}}}}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/audit", nil).WithContext(ctx), httptest.NewRecorder())
	for _, f := range []audit.Filter{{Scope: access.Scope{TenantID: 1}, From: time.Now().Add(-time.Hour), Until: time.Now()}, {Scope: access.Scope{TenantID: 1}, Source: "apple", Result: "failure", From: time.Now().Add(-time.Hour), Until: time.Now()}} {
		var body bytes.Buffer
		if err = Log(c, info, f, &audit.Page{Sources: []string{"apple", "activity"}}).Render(ctx, &body); err != nil {
			t.Fatal(err)
		}
		doc, err := html.Parse(strings.NewReader(body.String()))
		if err != nil {
			t.Fatal(err)
		}
		attribute := func(n *html.Node, key string) (string, bool) {
			for _, a := range n.Attr {
				if a.Key == key {
					return a.Val, true
				}
			}
			return "", false
		}
		var visit func(*html.Node)
		visit = func(n *html.Node) {
			if n.Type == html.ElementNode && n.Data == "select" {
				name, _ := attribute(n, "name")
				want, ok := map[string]string{"source": f.Source, "result": f.Result}[name]
				if ok {
					selected := []string{}
					for option := n.FirstChild; option != nil; option = option.NextSibling {
						if option.Type == html.ElementNode && option.Data == "option" {
							if _, exists := attribute(option, "selected"); exists {
								value, _ := attribute(option, "value")
								selected = append(selected, value)
							}
						}
					}
					if want == "" {
						if len(selected) != 0 {
							t.Errorf("default %s selected arbitrary options: %v", name, selected)
						}
					} else if len(selected) != 1 || selected[0] != want {
						t.Errorf("%s selected %v, want %q", name, selected, want)
					}
				}
			}
			for child := n.FirstChild; child != nil; child = child.NextSibling {
				visit(child)
			}
		}
		visit(doc)
	}
}
