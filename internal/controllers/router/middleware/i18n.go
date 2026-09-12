package middleware

import (
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/locales"
)

func GetLocale(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		accept := c.Request().Header.Get("Accept-Language")
		ctx, err := locales.WithLocale(c.Request().Context(), accept)
		if err != nil {
			return err
		}
		c.SetRequest(c.Request().WithContext(ctx))
		return next(c)
	}
}
