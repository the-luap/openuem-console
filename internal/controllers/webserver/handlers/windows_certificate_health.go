package handlers

import (
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

func windowsCertificateHealthOptions(raw string, force bool) (windows.CertificateHealthOptions, error) {
	o := windows.CertificateHealthOptions{Filter: "attention", WithinDays: 30, Limit: 26}
	invalid := echo.NewHTTPError(400, "Invalid certificate health filters")
	q, err := url.ParseQuery(raw)
	if err != nil || force {
		return o, invalid
	}
	for name, values := range q {
		if !slices.Contains([]string{"q", "filter", "days", "offset"}, name) || len(values) != 1 {
			return o, invalid
		}
	}
	o.Search = q.Get("q")
	if len(o.Search) > 128 || !utf8.ValidString(o.Search) || strings.IndexFunc(o.Search, unicode.IsControl) >= 0 {
		return o, invalid
	}
	if q.Has("filter") {
		o.Filter = q.Get("filter")
		if !slices.Contains([]string{"all", "attention", "renewal_due", "expires_soon", "expired", "pending", "retired"}, o.Filter) {
			return o, invalid
		}
	}
	for name, target := range map[string]*int{"days": &o.WithinDays, "offset": &o.Offset} {
		if q.Has(name) {
			n, err := strconv.Atoi(q.Get(name))
			if err != nil || strconv.Itoa(n) != q.Get(name) {
				return o, invalid
			}
			*target = n
		}
	}
	if o.WithinDays < 1 || o.WithinDays > 365 || o.Offset < 0 || o.Offset > 100000 {
		return o, invalid
	}
	return o, nil
}

func (h *Handler) WindowsCertificateHealth(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	o, err := windowsCertificateHealthOptions(c.Request().URL.RawQuery, c.Request().URL.ForceQuery)
	if err != nil {
		return err
	}
	r, err := h.Windows.CertificateHealth(c.Request().Context(), h.appleActor(c), scope, o)
	if errors.Is(err, windows.ErrCSPConflict) {
		return echo.NewHTTPError(409, "A certificate changed while this page was being read. Refresh the certificate health view.")
	}
	if err != nil {
		return windowsFailure(err)
	}
	more := len(r.Devices) > 25
	if more {
		r.Devices = r.Devices[:25]
	}
	return renderApple(c, windows_views.CertificateHealth(c, info, *r, o, more))
}
