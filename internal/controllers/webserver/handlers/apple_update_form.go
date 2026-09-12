package handlers

import (
	"net/http"
	"strings"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

func appleUpdateForm(c echo.Context) (*apple.UpdatePolicy, error) {
	f, err := deviceManagementForm(c, "updates.invalid_form", []string{"csrf", "remove", "target_release", "deadline", "details_url"})
	if err != nil {
		return nil, err
	}
	invalid := func() (*apple.UpdatePolicy, error) {
		return nil, echo.NewHTTPError(http.StatusBadRequest, i18n.T(c.Request().Context(), "updates.invalid_form"))
	}
	if _, removing := f["remove"]; removing {
		if f.Get("remove") != "true" || len(f) != 2 {
			return invalid()
		}
		return nil, nil
	}
	version, build, selected := strings.Cut(f.Get("target_release"), "/")
	if !selected || version == "" || build == "" || strings.Contains(build, "/") || f.Get("deadline") == "" {
		return invalid()
	}
	deadline := f.Get("deadline")
	if len(deadline) == 16 {
		deadline += ":00"
	}
	return &apple.UpdatePolicy{TargetVersion: version, TargetBuild: build, Deadline: deadline, DetailsURL: f.Get("details_url")}, nil
}
