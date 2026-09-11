package mdm_views

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

func TestTimestampsRetainUTCAndMissingEvidenceWithoutJavaScript(t *testing.T) {
	if err := ctxi18n.LoadWithDefault(locales.Content, "en"); err != nil {
		t.Fatal(err)
	}
	offset := time.Date(2026, 1, 2, 8, 34, 56, 0, time.FixedZone("Fixture offset", 19800))
	before := time.Date(2026, 3, 29, 0, 30, 0, 0, time.UTC)
	after := before.Add(time.Hour)
	for _, language := range preferences.Languages() {
		ctx, err := ctxi18n.WithLocale(context.Background(), language.Code)
		if err != nil {
			t.Fatal(err)
		}
		var body bytes.Buffer
		fmt.Fprintf(&body, `<!doctype html><html lang="%s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><script src="/assets/js/timestamps.js" defer></script></head><body><main><h1>Reported times</h1>`, language.Code)
		for index, value := range []*time.Time{&offset, &before, &after, nil, &offset} {
			fmt.Fprintf(&body, `<p id="time-%d">`, index)
			component := Timestamp(value)
			if index == 4 {
				component = TimestampSeconds(value)
			}
			if err = component.Render(ctx, &body); err != nil {
				t.Fatal(err)
			}
			body.WriteString("</p>")
		}
		body.WriteString(`<p id="device-deadline">Device-local update deadline: <span>2026-03-29T02:30:00</span></p></main></body></html>`)
		html := body.String()
		for _, literal := range []string{`datetime="2026-01-02T03:04:56Z"`, `datetime="2026-03-29T00:30:00Z"`, `datetime="2026-03-29T01:30:00Z"`, "2026-01-02 03:04 UTC", "2026-01-02 03:04:56 UTC", "Never reported", "2026-03-29T02:30:00"} {
			if !strings.Contains(html, literal) {
				t.Fatal("timestamp or fallback changed", language.Code, literal)
			}
		}
		if strings.Count(html, "<time ") != 4 {
			t.Fatal("missing report was converted to a date")
		}
		if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
			if err = os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(dir, "timestamps-"+language.Code+".html"), body.Bytes(), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
}
