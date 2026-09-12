package handlers

import (
	"net/url"

	"github.com/a-h/templ"
	"github.com/labstack/echo/v4"
)

// Preserve cache policy explicitly selected by a sensitive endpoint. Rendering
// must not weaken no-store to no-cache, which still permits response storage.
func renderHeaders(c echo.Context) {
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMETextHTML)
	c.Response().Header().Set(echo.HeaderXContentTypeOptions, "nosniff")
	if c.Response().Header().Get(echo.HeaderCacheControl) == "" {
		c.Response().Header().Set(echo.HeaderCacheControl, "no-cache")
	}
}

func RenderView(c echo.Context, cmp templ.Component) error {
	renderHeaders(c)
	return cmp.Render(c.Request().Context(), c.Response().Writer)
}

func RenderViewWithReplaceUrl(c echo.Context, cmp templ.Component, url *url.URL) error {
	renderHeaders(c)
	c.Response().Header().Set("HX-Replace-Url", url.String())
	return cmp.Render(c.Request().Context(), c.Response().Writer)
}

func RenderLogin(c echo.Context, cmp templ.Component) error {
	renderHeaders(c)
	c.Response().Header().Set("HX-Retarget", "body")
	c.Response().Header().Set("HX-Reswap", "outerHTML show:window:top")
	return cmp.Render(c.Request().Context(), c.Response().Writer)
}

func RenderError(c echo.Context, cmp templ.Component) error {
	renderHeaders(c)
	c.Response().Header().Set("HX-Retarget", "#error")
	c.Response().Header().Set("HX-Reswap", "outerHTML show:window:top")
	return cmp.Render(c.Request().Context(), c.Response().Writer)
}

func RenderConfirm(c echo.Context, cmp templ.Component) error {
	renderHeaders(c)
	c.Response().Header().Set("HX-Retarget", "#confirm")
	c.Response().Header().Set("HX-Reswap", "outerHTML show:window:top")
	return cmp.Render(c.Request().Context(), c.Response().Writer)
}

func RenderSuccess(c echo.Context, cmp templ.Component) error {
	renderHeaders(c)
	c.Response().Header().Set("HX-Retarget", "#success")
	c.Response().Header().Set("HX-Reswap", "outerHTML show:window:top")
	return cmp.Render(c.Request().Context(), c.Response().Writer)
}

func RenderLoginPartial(c echo.Context, cmp templ.Component) error {
	renderHeaders(c)
	c.Response().Header().Set("HX-Retarget", "#login")
	c.Response().Header().Set("HX-Reswap", "outerHTML")
	return cmp.Render(c.Request().Context(), c.Response().Writer)
}

func RenderAccountPartial(c echo.Context, cmp templ.Component) error {
	renderHeaders(c)
	c.Response().Header().Set("HX-Retarget", "#account")
	c.Response().Header().Set("HX-Reswap", "outerHTML")
	return cmp.Render(c.Request().Context(), c.Response().Writer)
}
