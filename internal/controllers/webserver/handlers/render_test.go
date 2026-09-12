package handlers

import (
	"context"
	"io"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/a-h/templ"
	"github.com/labstack/echo/v4"
)

func TestRenderPreservesEndpointCachePolicy(t *testing.T) {
	component := templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		_, err := io.WriteString(w, "<p>Protected content</p>")
		return err
	})
	renderers := map[string]func(echo.Context, templ.Component) error{
		"view": RenderView, "login": RenderLogin, "error": RenderError, "confirm": RenderConfirm, "success": RenderSuccess, "login-partial": RenderLoginPartial, "account-partial": RenderAccountPartial,
		"replace-url": func(c echo.Context, cmp templ.Component) error {
			return RenderViewWithReplaceUrl(c, cmp, &url.URL{Path: "/devices"})
		},
	}
	for name, render := range renderers {
		for _, policy := range []string{"", "no-store", "private, no-store, max-age=0"} {
			t.Run(name+"/"+policy, func(t *testing.T) {
				rec := httptest.NewRecorder()
				c := echo.New().NewContext(httptest.NewRequest("GET", "/protected", nil), rec)
				if policy != "" {
					c.Response().Header().Set("Cache-Control", policy)
				}
				if err := render(c, component); err != nil {
					t.Fatal(err)
				}
				expected := policy
				if expected == "" {
					expected = "no-cache"
				}
				if rec.Result().Header.Get("Cache-Control") != expected {
					t.Fatal("rendering weakened endpoint cache policy", rec.Result().Header.Get("Cache-Control"))
				}
				if rec.Body.String() != "<p>Protected content</p>" || rec.Result().Header.Get("X-Content-Type-Options") != "nosniff" {
					t.Fatal("rendered response incomplete")
				}
			})
		}
	}
}
