package handlers

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	consolemiddleware "github.com/open-uem/openuem-console/internal/controllers/router/middleware"
	"github.com/open-uem/openuem-console/internal/views/locales"
)

// This opt-in loopback TLS fixture shares the isolated database created by the
// console integration test. Authentication is supplied by the fixture; forms use
// production handlers and the real cookie/Origin CSRF middleware. Creating the
// private <path>.stop file closes the server and permits schema cleanup.
func runDesktopBrowserFixture(t *testing.T, h *Handler, ctx context.Context) {
	t.Helper()
	runConsoleBrowserFixture(t, h, ctx, os.Getenv("OPENUEM_DESKTOP_BROWSER_FIXTURE"), "")
}

func runConsoleBrowserFixture(t *testing.T, h *Handler, ctx context.Context, path, entry string) {
	t.Helper()
	if path == "" {
		return
	}
	if entry == "" {
		tenant, err := h.Model.Client.Tenant.Create().SetDescription("Browser acceptance organization").Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = h.Model.CloneGlobalSettings(tenant.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = h.Model.Client.Site.Create().SetDescription("Browser acceptance site").SetTenantID(tenant.ID).SetIsDefault(true).Save(ctx); err != nil {
			t.Fatal(err)
		}
		entry = "/tenant/" + strconv.Itoa(tenant.ID) + "/desktop/enrollment"
	}
	e := echo.New()
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			requestCtx, err := locales.WithLocale(c.Request().Context(), "en")
			if err != nil {
				return err
			}
			requestCtx, err = h.SessionManager.Manager.Load(requestCtx, "")
			if err != nil {
				return err
			}
			stampOwnedConsoleSession(t, h, requestCtx, "apple-console-admin")
			c.SetRequest(c.Request().WithContext(requestCtx))
			return next(c)
		}
	}, consolemiddleware.CSRF())
	assets, err := filepath.Abs("../../../../assets")
	if err != nil {
		t.Fatal(err)
	}
	e.Static("/assets", assets)
	h.Register(e, 3)
	previous := h.PublicOrigin
	var server *httptest.Server
	if os.Getenv("OPENUEM_DESKTOP_BROWSER_HTTP") == "1" {
		// A separate loopback-only browser fixture avoids changing browser or
		// system certificate trust. Its public enrollment origin stays HTTPS;
		// production gateway/claim TLS is exercised by the protocol tests.
		server = httptest.NewServer(e)
	} else {
		server = httptest.NewTLSServer(e)
		h.PublicOrigin = server.URL
	}
	defer func() {
		// Stop and join HTTP handlers before restoring shared configuration.
		server.Close()
		h.PublicOrigin = previous
	}()
	url := strings.Replace(server.URL, "127.0.0.1", "localhost", 1)
	if err = os.WriteFile(path, []byte(url+entry), 0600); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(path); _ = os.Remove(path + ".stop") }()
	t.Log("Console browser fixture is ready; its loopback URL is in the configured file")
	deadline := time.NewTimer(8 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("console browser fixture timed out; its isolated schema will be removed")
		case <-ticker.C:
			if _, err := os.Stat(path + ".stop"); err == nil {
				return
			}
		}
	}
}
