package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/controllers/router"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

func TestAppleErrorsKeepUnknownCausesOutOfResponses(t *testing.T) {
	const secret = "owned-private-apple-error-canary"
	for _, failure := range []struct {
		name   string
		err    error
		status int
	}{
		{"database", errors.New("database password=" + secret), 400},
		{"transport", &url.Error{Op: "Post", URL: "https://push.example.test/3/device/" + secret, Err: errors.New("connection reset")}, 400},
		{"crypto", fmt.Errorf("cannot decrypt private material %s", secret), 400},
		{"missing resource", fmt.Errorf("%s: %w", secret, apple.ErrNotFound), 404},
		{"conflict", fmt.Errorf("%s: %w", secret, apple.ErrConflict), 409},
	} {
		t.Run(failure.name, func(t *testing.T) {
			e := router.New(&sessions.SessionManager{Manager: scs.New()}, "console.test", "443", "1M")
			e.GET("/owned-error", func(c echo.Context) error { return appleFailure(c, failure.err) })
			e.GET("/owned-setup", func(c echo.Context) error { return c.String(http.StatusOK, appleSetupMessage(c, failure.err)) })
			for _, path := range []string{"/owned-error", "/owned-setup"} {
				rec := httptest.NewRecorder()
				e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://console.test"+path, nil))
				want := failure.status
				if path == "/owned-setup" {
					want = 200
				}
				if rec.Code != want {
					t.Fatal("Apple failure changed status", rec.Code)
				}
				if strings.Contains(rec.Body.String(), secret) || strings.Contains(rec.Body.String(), "push.example.test") {
					t.Error("Apple response exposed an internal cause", path)
				}
			}
		})
	}
}

func TestAppleSetupKeepsKnownGuidanceWithoutWrappedDetails(t *testing.T) {
	const secret = "owned-private-setup-canary"
	for _, known := range []struct {
		err  error
		want string
	}{
		{apple.ErrPushCertificate, apple.ErrPushCertificate.Error()},
		{apple.ErrPushConnection, apple.ErrPushConnection.Error()},
		{apple.ErrPushOrganization, "Select an organization"},
		{apple.ErrPushPublicURL, "HTTPS origin"},
		{apple.ErrPushOrganizationName, "255 characters"},
		{apple.ErrPushKeyPair, "matching APNs certificate"},
		{apple.ErrPushTopicMissing, "Apple MDM push topic"},
		{apple.ErrPushValidity, "validity period"},
		{apple.ErrPushTopicChanged, "existing push topic"},
		{apple.ErrPushURLInUse, "active ADE profiles"},
	} {
		c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/ios/setup", nil), httptest.NewRecorder())
		message := appleSetupMessage(c, fmt.Errorf("%s: %w", secret, known.err))
		if !strings.Contains(message, known.want) || strings.Contains(message, secret) || strings.Contains(message, "MISSING") {
			t.Fatal("setup lost safe known guidance", known.err, message)
		}
		message = appleSetupMessage(c, errors.New(known.err.Error()+": "+secret))
		if strings.Contains(message, secret) || !strings.Contains(message, "Refresh the page") {
			t.Fatal("an untyped error impersonated trusted setup guidance")
		}
	}
}
