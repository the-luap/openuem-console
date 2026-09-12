package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func exerciseWindowsUnenrollment(t *testing.T, h *Handler, ctx context.Context, scope access.Scope, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	t.Run("Windows disconnection report retains scoped device and command history", func(t *testing.T) {
		deviceID, deliver, disconnect := windowsConsoleProtocolPeer(t, h, ctx, scope)
		active := deliver(windows.CSPCommandSpec{Kind: "Get", URI: "./DevDetail/SwV"}, "")
		disconnect()
		base := fmt.Sprintf("/tenant/%d/site/%d", scope.TenantID, scope.SiteID)
		path := base + "/windows/" + deviceID
		report, err := h.Windows.UnenrollmentReport(ctx, "organization-admin", scope, deviceID)
		if err != nil || report.InterruptedSessionID == "" {
			t.Fatal("disconnection report lost interrupted work", err)
		}
		for _, user := range []string{"apple-console-admin", "organization-admin", "scoped-operator", "scoped-viewer"} {
			w := request(user, "GET", path, nil)
			if w.Code != 200 {
				t.Fatal("scoped disconnection detail failed", user, w.Code)
			}
			for _, want := range []string{"Device disconnection reported", "Disconnection reported; access revoked", "has not been independently verified", report.ID, report.FingerprintSHA256, "&lt;script&gt;peer&lt;/script&gt;"} {
				if !strings.Contains(w.Body.String(), want) {
					t.Fatal("disconnection evidence meaning lost", want)
				}
			}
			for _, absent := range []string{"<script>peer</script>", `name="confirm_revoke"`, "unenrollment completed", "PRIVATE KEY", "AAUTHSECRET"} {
				if strings.Contains(w.Body.String(), absent) {
					t.Fatal("disconnection view exposed content or false completion", absent)
				}
			}
			if w := request(user, "GET", base+"/devices?platform=windows", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Native MDM: Disconnection reported; access revoked") {
				t.Fatal("unified inventory lost disconnection status", w.Code)
			}
		}
		detail, err := h.Windows.CSPCommandDetails(ctx, "organization-admin", scope, deviceID, active.Command.ID)
		if err != nil || detail.Command.Phase != "unknown" {
			t.Fatal("interrupted command history was not retained", err)
		}
		if w := request("organization-admin", "GET", path+"/commands/"+active.Command.ID, nil); w.Code != 200 {
			t.Fatal("disconnected device lost command history", w.Code)
		}
		if w := request("scoped-operator", "GET", path+"/updates/new", nil); w.Code != 409 {
			t.Fatal("disconnected device admitted new policy work", w.Code)
		}
		sibling, err := h.Model.Client.Site.Create().SetDescription("Disconnection sibling").SetTenantID(scope.TenantID).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if w := request("organization-admin", "GET", fmt.Sprintf("/tenant/%d/site/%d/windows/%s", scope.TenantID, sibling.ID, deviceID), nil); w.Code != 404 {
			t.Fatal("disconnection detail crossed site", w.Code)
		}
		artifact("windows-disconnection", request("organization-admin", "GET", path, nil))
		runConsoleBrowserFixture(t, h, ctx, os.Getenv("OPENUEM_WINDOWS_UNENROLLMENT_BROWSER_FIXTURE"), path)
	})
}
