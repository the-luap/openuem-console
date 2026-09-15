package mdm_views

import (
	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/views/locales"
)

// Stored diagnostics can predate redaction or contain a transport URL/token.
// Display only fixed guidance derived from the delivery state, never that text.
func pushErrorText(c echo.Context, status string) string {
	key := "apple_errors.push_problem"
	switch status {
	case "failed":
		key = "apple_errors.push_failed"
	case "invalid_token":
		key = "apple_errors.push_invalid"
	}
	ctx := c.Request().Context()
	if i18n.GetLocale(ctx) == nil {
		if english, err := locales.WithLocale(ctx, "en"); err == nil {
			ctx = english
		}
	}
	if !i18n.Has(ctx, key) {
		return "Review the current push status and Apple push settings."
	}
	return i18n.T(ctx, key)
}
