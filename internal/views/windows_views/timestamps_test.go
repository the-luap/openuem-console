package windows_views

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/invopop/ctxi18n"
	"github.com/open-uem/openuem-console/internal/preferences"
	"github.com/open-uem/openuem-console/internal/views/locales"
)

func TestWindowsTimestampsPreserveSchedulingPrecision(t *testing.T) {
	if err := ctxi18n.LoadWithDefault(locales.Content, "en"); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	for _, language := range preferences.Languages() {
		ctx, err := ctxi18n.WithLocale(context.Background(), language.Code)
		if err != nil {
			t.Fatal(err)
		}
		var body bytes.Buffer
		fmt.Fprintf(&body, `<!doctype html><html lang="%s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><script src="/assets/js/timestamps.js" defer></script></head><body><main><h1>Windows command times</h1>`, language.Code)
		for index, nanos := range []time.Duration{0, 123456789, 1} {
			fmt.Fprintf(&body, `<p id="precise-%d">`, index)
			if err = ScheduleTime(base.Add(nanos)).Render(ctx, &body); err != nil {
				t.Fatal(err)
			}
			body.WriteString("</p>")
		}
		body.WriteString(`<p id="minute">`)
		if err = ReportTime(base).Render(ctx, &body); err != nil {
			t.Fatal(err)
		}
		body.WriteString(`</p><p id="missing">`)
		if err = OptionalReportTime(nil).Render(ctx, &body); err != nil {
			t.Fatal(err)
		}
		body.WriteString(`</p></main></body></html>`)
		html := body.String()
		for _, literal := range []string{`datetime="2026-12-31T23:59:59.123456789Z"`, `datetime="2026-12-31T23:59:59.000000001Z"`, "2026-12-31 23:59:59.123456789 UTC", "2026-12-31 23:59:59.000000001 UTC", "2026-12-31 23:59 UTC", "Not received"} {
			if !strings.Contains(html, literal) {
				t.Fatal("Windows timestamp precision or missing evidence changed", language.Code, literal)
			}
		}
		if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
			if err = os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(dir, "windows-timestamps-"+language.Code+".html"), body.Bytes(), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func writeWindowsBrowserFixture(t *testing.T, name string, body []byte) {
	t.Helper()
	if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".html"), body, 0644); err != nil {
			t.Fatal(err)
		}
	}
}
