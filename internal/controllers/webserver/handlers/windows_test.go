package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestWindowsConsoleRoutesHaveExplicitCapabilities(t *testing.T) {
	h := &Handler{}
	e := echo.New()
	h.RegisterWindows(e)
	want := map[string]access.Capability{"GET /windows": access.ReadDevices, "GET /windows/:id": access.ReadDevices, "POST /windows/setup": access.ManageCertificates, "POST /windows/invitations": access.EnrollDevices, "POST /windows/invitations/:id/revoke": access.EnrollDevices, "POST /windows/:id/revoke": access.RevokeDevices, "GET /windows/:id/updates": access.ManageUpdates, "GET /windows/:id/updates/:run": access.ManageUpdates, "POST /windows/:id/updates/:run/cancel": access.ManageUpdates, "GET /windows/:id/updates/new": access.ManageUpdates, "POST /windows/:id/updates/preview": access.ManageUpdates, "POST /windows/:id/updates/create": access.ManageUpdates}
	for _, route := range []string{"GET /windows/update-rings", "GET /windows/update-rings/new", "GET /windows/update-rings/:ring", "GET /windows/update-rings/:ring/edit", "POST /windows/update-rings/preview", "POST /windows/update-rings/save", "GET /windows/update-rings/:ring/assign", "POST /windows/update-rings/:ring/assign/preview", "POST /windows/update-rings/:ring/assign/create", "GET /windows/update-rollouts/:rollout", "GET /windows/update-rings/:ring/schedule", "POST /windows/update-rings/:ring/schedule/preview", "POST /windows/update-rings/:ring/schedule/create", "GET /windows/update-schedules", "GET /windows/update-schedules/:schedule", "POST /windows/update-schedules/:schedule/cancel"} {
		want[route] = access.ManageUpdates
	}
	for _, route := range []string{"GET /windows/:id/commands/new", "POST /windows/:id/commands/preview", "POST /windows/:id/commands/create", "GET /windows/:id/commands", "GET /windows/:id/commands/:command", "POST /windows/:id/commands/:command/cancel", "POST /windows/:id/commands/:command/abandon"} {
		want[route] = access.ManageWindowsCSP
	}
	count := 0
	for _, r := range e.Routes() {
		if r.Method == echo.RouteNotFound {
			if _, ok := windowsCapability(r.Method, r.Path); ok {
				t.Fatal("fallback route inherited Windows authority")
			}
			continue
		}
		count++
		cap, ok := windowsCapability(r.Method, r.Path)
		expected, present := want[r.Method+" "+appleRoute(r.Path)]
		if !ok || !present || cap != expected {
			t.Fatal("unmapped Windows route", r.Method, r.Path)
		}
	}
	if count != len(want)*3 {
		t.Fatal("unexpected native Windows route count", count)
	}
	for route := range want {
		method, path, _ := strings.Cut(route, " ")
		for _, bad := range []string{path + "/extra", strings.Replace(path, "windows", "window", 1)} {
			if _, ok := windowsCapability(method, bad); ok {
				t.Fatal("unknown route inherited Windows authority")
			}
		}
	}
	for _, method := range []string{"HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"} {
		if _, ok := windowsCapability(method, "/windows/setup"); ok {
			t.Fatal("unregistered method inherited Windows authority")
		}
	}
}

func TestWindowsFormsRequireBoundedBodyCSRFAndUniqueFields(t *testing.T) {
	for name, test := range map[string]struct {
		body, query, mime string
		change            func(*http.Request)
		status            int
	}{
		"valid":              {"csrf=expected&username=user%40example.test&hours=1", "", "application/x-www-form-urlencoded", nil, 204},
		"missing token":      {"username=user%40example.test", "", "application/x-www-form-urlencoded", nil, 403},
		"query token":        {"username=user%40example.test", "csrf=expected", "application/x-www-form-urlencoded", nil, 400},
		"duplicate token":    {"csrf=expected&csrf=expected", "", "application/x-www-form-urlencoded", nil, 403},
		"duplicate field":    {"csrf=expected&hours=1&hours=2", "", "application/x-www-form-urlencoded", nil, 400},
		"unknown field":      {"csrf=expected&tenant=2", "", "application/x-www-form-urlencoded", nil, 400},
		"oversized declared": {"csrf=expected&username=" + strings.Repeat("x", 8192), "", "application/x-www-form-urlencoded", nil, 413},
		"oversized stream":   {"csrf=expected&username=" + strings.Repeat("x", 8192), "", "application/x-www-form-urlencoded", func(r *http.Request) { r.ContentLength = -1 }, 413},
		"cached large form": {"csrf=expected", "", "application/x-www-form-urlencoded", func(r *http.Request) {
			r.PostForm = url.Values{"csrf": {"expected"}, "username": {strings.Repeat("x", 8192)}}
		}, 413},
		"JSON":           {"{}", "", "application/json", nil, 415},
		"multipart":      {"", "", "multipart/form-data; boundary=example", nil, 415},
		"duplicate MIME": {"csrf=expected", "", "application/x-www-form-urlencoded", func(r *http.Request) { r.Header.Add("Content-Type", "application/x-www-form-urlencoded") }, 415},
	} {
		t.Run(name, func(t *testing.T) {
			h := &Handler{}
			e := echo.New()
			e.POST("/windows/invitations", func(c echo.Context) error {
				if _, err := windowsForm(c, "username", "hours"); err != nil {
					return err
				}
				if deadline, ok := c.Request().Context().Deadline(); !ok || time.Until(deadline) > 30*time.Second {
					t.Error("unbounded Windows console request")
				}
				return c.NoContent(204)
			}, func(next echo.HandlerFunc) echo.HandlerFunc {
				return func(c echo.Context) error { c.Set("csrf", "expected"); return next(c) }
			}, h.WindowsCSRF)
			path := "/windows/invitations"
			if test.query != "" {
				path += "?" + test.query
			}
			r := httptest.NewRequest("POST", path, strings.NewReader(test.body))
			r.Header.Set("Content-Type", test.mime)
			if test.change != nil {
				test.change(r)
			}
			w := httptest.NewRecorder()
			e.ServeHTTP(w, r)
			if w.Code != test.status || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("Windows form boundary failed", w.Code)
			}
		})
	}
}
