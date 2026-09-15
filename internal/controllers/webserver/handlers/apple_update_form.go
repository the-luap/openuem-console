package handlers

import (
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

type appleUpdateSubmission struct {
	policy         *apple.UpdatePolicy
	expectedPolicy string
}

func appleUpdateForm(c echo.Context) (*appleUpdateSubmission, error) {
	f, err := deviceManagementForm(c, "updates.invalid_form", []string{"csrf", "expected_policy", "remove", "target_release", "deadline", "details_url"})
	if err != nil {
		return nil, err
	}
	invalid := func() (*appleUpdateSubmission, error) {
		return nil, echo.NewHTTPError(http.StatusBadRequest, i18n.T(c.Request().Context(), "updates.invalid_form"))
	}
	expected := f.Get("expected_policy")
	if len(expected) != 64 || expected != strings.ToLower(expected) {
		return invalid()
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return invalid()
	}
	if _, removing := f["remove"]; removing {
		if f.Get("remove") != "true" || len(f) != 3 {
			return invalid()
		}
		return &appleUpdateSubmission{expectedPolicy: expected}, nil
	}
	version, build, selected := strings.Cut(f.Get("target_release"), "/")
	if !selected || version == "" || build == "" || strings.Contains(build, "/") || f.Get("deadline") == "" {
		return invalid()
	}
	deadline := f.Get("deadline")
	if len(deadline) == 16 {
		deadline += ":00"
	}
	return &appleUpdateSubmission{expectedPolicy: expected, policy: &apple.UpdatePolicy{TargetVersion: version, TargetBuild: build, Deadline: deadline, DetailsURL: f.Get("details_url")}}, nil
}
