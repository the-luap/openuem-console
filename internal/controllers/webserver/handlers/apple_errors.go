package handlers

import (
	"errors"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/views/locales"
)

func appleErrorText(c echo.Context, key string) string {
	ctx := c.Request().Context()
	if i18n.GetLocale(ctx) == nil {
		if english, err := locales.WithLocale(ctx, "en"); err == nil {
			ctx = english
		}
	}
	if !i18n.Has(ctx, key) {
		return "Apple management could not complete the request. Refresh the page to check its status."
	}
	return i18n.T(ctx, key)
}

func appleSetupMessage(c echo.Context, err error) string {
	// These fixed, established certificate/connection messages contain no input
	// or wrapped cause. Preserve their precise remediation and rollback advice.
	for _, known := range []error{apple.ErrPushCertificate, apple.ErrPushConnection} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	for _, known := range []struct {
		err error
		key string
	}{
		{apple.ErrPushOrganization, "organization"},
		{apple.ErrPushPublicURL, "public_url"},
		{apple.ErrPushOrganizationName, "organization_name"},
		{apple.ErrPushKeyPair, "key_pair"},
		{apple.ErrPushTopicMissing, "topic_missing"},
		{apple.ErrPushValidity, "validity"},
		{apple.ErrPushTopicChanged, "topic_changed"},
		{apple.ErrPushURLInUse, "url_in_use"},
	} {
		if errors.Is(err, known.err) {
			return appleErrorText(c, "apple_errors."+known.key)
		}
	}
	return appleErrorText(c, "apple_errors.setup")
}
