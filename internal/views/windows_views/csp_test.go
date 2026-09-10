package windows_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/invopop/ctxi18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func TestWindowsCSPViewsPreserveUntrustedValuesAndOutcomeBoundaries(t *testing.T) {
	if err := ctxi18n.LoadWithDefault(locales.Content, "en"); err != nil {
		t.Fatal(err)
	}
	ctx, err := ctxi18n.WithLocale(context.Background(), "en")
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	scope := access.Scope{TenantID: 1, SiteID: 11}
	info := &partials.CommonInfo{Principal: access.Principal{UserID: "synthetic-admin", Grants: []access.Grant{{Role: access.TenantAdmin, Scope: access.Scope{TenantID: 1}}}}, SM: &sessions.SessionManager{Manager: sm}, TenantID: "1", SiteID: "11", CSRFToken: "synthetic-csrf"}
	c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/11/windows/test/commands/test", nil).WithContext(ctx), httptest.NewRecorder())
	now := time.Date(2026, 9, 10, 12, 13, 14, 123456000, time.UTC)
	device := windows.DeviceMetadata{ID: "10000000-0000-4000-8000-000000000001", Name: "<script>device</script>"}
	for _, phase := range []string{"queued", "blocked", "sent", "acknowledged", "failed", "unknown", "abandoned", "canceled", "expired"} {
		t.Run(phase, func(t *testing.T) {
			command := windows.CSPCommand{ID: "20000000-0000-4000-8000-000000000001", DeviceID: device.ID, Scope: scope, Revision: 7, Phase: phase, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
			detail := windows.CSPCommandDetail{Command: command, Reason: "<script>reason</script>", Request: windows.SyncMLCommand{Kind: "Sequence", Commands: []windows.SyncMLCommand{{Kind: "Replace", Items: []windows.SyncMLItem{{Target: &windows.SyncMLLocation{URI: "./Device/Vendor/MSFT/Test/Value"}, Data: &windows.SyncMLData{Text: "  <script>intent</script>\n"}}}}, {Kind: "Atomic", Commands: []windows.SyncMLCommand{{Kind: "Delete"}}}}}, Outcomes: []windows.CSPOperationOutcome{
				{Kind: "Get", CommandID: "wire-one", ParentID: "wire-parent", Status: 200, Format: "xml", Data: &windows.SyncMLData{XML: `<img src="x" onerror="alert(1)"/>`}},
				{Kind: "Get", CommandID: "wire-two", Status: 202, Incomplete: true, Data: &windows.SyncMLData{Text: "PARTIAL_VALUE_MUST_NOT_ESCAPE"}},
				{Kind: "Get", CommandID: "wire-three", Status: 0},
				{Kind: "Get", CommandID: "wire-four", Status: 200, Data: &windows.SyncMLData{Text: ""}},
				{Kind: "Atomic", CommandID: "wire-parent", Status: 516, OriginalError: "<script>device error</script>"},
			}}
			if phase == "abandoned" {
				detail.Resolution = "<script>resolution</script>"
			}
			var out bytes.Buffer
			if err := CSPCommand(c, info, device, detail).Render(ctx, &out); err != nil {
				t.Fatal(err)
			}
			html := out.String()
			for _, value := range []string{"<script>device</script>", "<script>reason</script>", "<script>intent</script>", "<script>device error</script>", "<script>resolution</script>", `<img src="x"`, "PARTIAL_VALUE_MUST_NOT_ESCAPE"} {
				if strings.Contains(html, value) {
					t.Fatal("untrusted or partial payload escaped")
				}
			}
			for _, want := range []string{cspState(phase), "Operation 1.2.1", "&lt;script&gt;intent&lt;/script&gt;", "wire-parent", "Incomplete result; partial value withheld.", "No complete result received.", "No status received", "Text value · 0 bytes", "Empty value", "516", "202", "2026-09-10 12:13:14.123456 UTC", "Download command evidence (JSON)", "The download contains unencrypted configuration", "/tenant/1/site/11/windows/" + device.ID + "/commands/" + command.ID + "/export"} {
				if !strings.Contains(html, want) {
					t.Fatal("CSP meaning lost", want)
				}
			}
			if strings.Contains(html, `name="confirm_cancel"`) != (phase == "queued" || phase == "blocked") || strings.Contains(html, `name="confirm_abandon"`) != (phase == "unknown") {
				t.Fatal("unsafe CSP action offered")
			}
			if (phase == "queued" || phase == "blocked" || phase == "unknown") && !strings.Contains(html, `name="expected_revision" value="7"`) {
				t.Fatal("action lost reviewed revision")
			}
			if phase == "abandoned" && !strings.Contains(html, "&lt;script&gt;resolution&lt;/script&gt;") {
				t.Fatal("resolution history lost")
			}
			out.Reset()
			observation := windows.CSPObservation{SessionID: "synthetic-session", MessageID: 3, ReceivedAt: now, Outcome: "", StopReason: "<script>stop</script>", Outcomes: detail.Outcomes}
			if err := CSPObservation(c, info, device, command, observation).Render(ctx, &out); err != nil {
				t.Fatal(err)
			}
			html = out.String()
			for _, value := range []string{"PARTIAL_VALUE_MUST_NOT_ESCAPE", "<script>stop</script>", "<script>device</script>", `<img src="x"`, `name="confirm_abandon"`, `name="confirm_cancel"`, cspState(phase)} {
				if strings.Contains(html, value) {
					t.Fatal("historical view exposed content, action or later state", value)
				}
			}
			for _, want := range []string{"Evidence incomplete", "&lt;script&gt;stop&lt;/script&gt;", "Incomplete result; partial value withheld.", "Empty value", "No complete result received.", "2026-09-10 12:13:14.123456 UTC", "516", "Download this observation (JSON)", "/observations/3/export"} {
				if !strings.Contains(html, want) {
					t.Fatal("historical evidence distinction lost", want)
				}
			}
		})
	}
	for _, phase := range []string{"queued", "blocked", "unknown"} {
		command := windows.CSPCommand{ID: "20000000-0000-4000-8000-000000000001", DeviceID: device.ID, UnenrollmentRequestID: "20000000-0000-4000-8000-000000000001", Scope: scope, Revision: 2, Phase: phase, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
		var out bytes.Buffer
		if err := CSPCommand(c, info, device, windows.CSPCommandDetail{Command: command, Request: windows.SyncMLCommand{Kind: "Exec"}}).Render(ctx, &out); err != nil {
			t.Fatal(err)
		}
		html := out.String()
		if canCancelCSP(command) || strings.Contains(html, `name="confirm_cancel"`) || strings.Contains(html, `name="confirm_abandon"`) || !strings.Contains(html, "A command acknowledgment does not prove local cleanup") {
			t.Fatal("typed disconnection acquired raw actions or lost meaning")
		}
	}
	if canCancelCSP(windows.CSPCommand{Phase: "queued", UpdateRunID: "owned-run"}) {
		t.Fatal("typed step acquired raw cancellation")
	}
}
