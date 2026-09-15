package audit_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"golang.org/x/net/html"
)

func auditViewTestContext(t *testing.T) (context.Context, echo.Context, *partials.CommonInfo) {
	t.Helper()
	if err := locales.Load(); err != nil {
		t.Fatal(err)
	}
	ctx, err := locales.WithLocale(t.Context(), "en")
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
	return ctx, c, info
}

func TestAuditFiltersRenderOnlyTheSelectedOption(t *testing.T) {
	ctx, c, info := auditViewTestContext(t)
	var err error
	for _, f := range []audit.Filter{{Scope: access.Scope{TenantID: 1}, From: time.Now().Add(-time.Hour), Until: time.Now()}, {Scope: access.Scope{TenantID: 1}, Source: "windows_csp", Result: "recorded", From: time.Now().Add(-time.Hour), Until: time.Now()}} {
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

func TestAuditRetentionRendersExplicitWindowsSelection(t *testing.T) {
	ctx, c, info := auditViewTestContext(t)
	for _, tc := range []struct {
		name    string
		scope   access.Scope
		policy  audit.RetentionPolicy
		preview *audit.RetentionPreview
		checked bool
		days    int
	}{
		{name: "default", scope: access.Scope{TenantID: 1}, days: 0},
		{name: "existing inclusion", scope: access.Scope{TenantID: 1}, policy: audit.RetentionPolicy{Days: 30, WindowsEnabled: true}, checked: true, days: 30},
		{name: "proposed inclusion", scope: access.Scope{TenantID: 1}, policy: audit.RetentionPolicy{Days: 60}, preview: &audit.RetentionPreview{Days: 30, WindowsEnabled: true}, checked: true, days: 30},
		{name: "proposed exclusion", scope: access.Scope{TenantID: 1}, policy: audit.RetentionPolicy{Days: 30, WindowsEnabled: true}, preview: &audit.RetentionPreview{Days: 60}, days: 60},
		{name: "stop cleanup", scope: access.Scope{TenantID: 1}, policy: audit.RetentionPolicy{Days: 30, WindowsEnabled: true}, preview: &audit.RetentionPreview{Days: 0}, days: 0},
		{name: "server policy", days: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body bytes.Buffer
			if err := Retention(c, info, tc.scope, tc.policy, nil, tc.preview).Render(ctx, &body); err != nil {
				t.Fatal(err)
			}
			doc, err := html.Parse(strings.NewReader(body.String()))
			if err != nil {
				t.Fatal(err)
			}
			found, foundDays := 0, false
			var visit func(*html.Node)
			visit = func(n *html.Node) {
				if n.Type == html.ElementNode && n.Data == "input" {
					attrs := map[string]string{}
					for _, a := range n.Attr {
						attrs[a.Key] = a.Val
					}
					switch attrs["name"] {
					case "include_windows":
						found++
						_, checked := attrs["checked"]
						if checked != tc.checked || attrs["type"] != "checkbox" || attrs["value"] != "yes" {
							t.Error("Windows selection differs from reviewed choice")
						}
					case "days":
						foundDays = true
						if attrs["value"] != strconv.Itoa(tc.days) {
							t.Error("preview reset the proposed days")
						}
					case "confirm":
						if _, checked := attrs["checked"]; checked {
							t.Error("permanent deletion confirmation was selected automatically")
						}
					}
				}
				for child := n.FirstChild; child != nil; child = child.NextSibling {
					visit(child)
				}
			}
			visit(doc)
			if !foundDays || tc.scope.TenantID == 0 && found != 0 || tc.scope.TenantID > 0 && found != 1 {
				t.Fatal("retention selection missing or available in wrong scope")
			}
		})
	}
}
