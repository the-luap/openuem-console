package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
)

func TestWindowsCSPJSONPreservesExactValuesAndTreeStructure(t *testing.T) {
	for _, raw := range []string{
		`{"kind":"Get","uri":"./DevInfo/DevId"}`,
		`{"kind":"Delete","uri":"./Device/Vendor/MSFT/Test/Value"}`,
		`{"kind":"Exec","uri":"./Device/Vendor/MSFT/Test/Run"}`,
		`{"kind":"Add","uri":"./Device/Vendor/MSFT/Test/Node","format":"node"}`,
		`{"kind":"Replace","uri":"./Device/Vendor/MSFT/Test/Value","format":"null","text":""}`,
		`{"kind":"Replace","uri":"./Device/Vendor/MSFT/Test/Value","format":"chr","text":""}`,
		`{"kind":"Replace","uri":"./Device/Vendor/MSFT/Test/Value","format":"int","text":"0"}`,
		`{"kind":"Replace","uri":"./Device/Vendor/MSFT/Test/Value","format":"bool","text":"false"}`,
		`{"kind":"Replace","uri":"./Device/Vendor/MSFT/Test/Value","format":"b64","text":"AAECAw=="}`,
		`{"kind":"Replace","uri":"./Device/Vendor/MSFT/Test/Value","format":"xml","mime":"application/xml","xml":"<x xmlns=\"urn:test\">&amp;value</x>"}`,
		`{"kind":"Sequence","commands":[{"kind":"Get","uri":"./DevInfo/Man"},{"kind":"Atomic","commands":[{"kind":"Replace","uri":"./User/Vendor/MSFT/Test/Value","format":"chr","text":"  <script>literal</script>\n\t"}]}]}`,
	} {
		spec, err := parseWindowsCSPJSON(raw)
		if err != nil {
			t.Fatal("valid JSON command rejected", err)
		}
		if _, err := windows.PreviewCSPCommand(spec); err != nil {
			t.Fatal("valid command failed shared compiler", err)
		}
	}
	for _, value := range []string{"", "0", "false", "  <script>literal</script>\n\t", "Hello ä 😀", `\ud800`, "\r\n"} {
		encoded, _ := json.Marshal(value)
		spec, err := parseWindowsCSPJSON(`{"kind":"Replace","uri":"./Device/Vendor/MSFT/Test/Value","format":"chr","text":` + string(encoded) + `}`)
		if err != nil || spec.Data == nil || spec.Data.Text != value {
			t.Fatal("requested data changed", err)
		}
	}
	spec, err := parseWindowsCSPJSON(`{"kind":"Replace","uri":"./Device/Vendor/MSFT/Test/Value","format":"chr","text":"\ud83d\ude00"}`)
	if err != nil || spec.Data.Text != "😀" {
		t.Fatal("valid UTF-16 pair changed", err)
	}
}

func TestWindowsCSPJSONRejectsAmbiguousAndExcessiveStructure(t *testing.T) {
	for _, raw := range []string{"", `null`, `[]`, `{} {}`, `{"kind":"Get","kind":"Exec"}`, `{"kind":"Get","\u006bind":"Exec"}`, `{"Kind":"Get"}`, `{"kind":null}`, `{"kind":1}`, `{"kind":"Get","uri":null}`, `{"kind":"Get","data":"x"}`, `{"kind":"Get","commands":[]}`, `{"kind":"Atomic","commands":null}`, `{"kind":"Atomic","commands":[null]}`, `{"kind":"Atomic","commands":[{}]}`, `{"kind":"Atomic","uri":"","commands":[{"kind":"Get"}]}`, `{"kind":"Replace","text":"","xml":""}`, `{"kind":"Replace","format":"chr","xml":""}`, `{"kind":"Replace","format":"xml","xml":""}`, `{"kind":"Replace","text":"\ud800"}`, `{"kind":"Replace","text":"\udc00"}`, `{"kind":"Replace","text":"\ud800\u0061"}`, "{\"kind\":\"\xff\"}", strings.Repeat(" ", maxWindowsCSPJSONBytes) + `{}`} {
		if _, err := parseWindowsCSPJSON(raw); err == nil {
			t.Fatal("ambiguous JSON command admitted")
		}
	}
	leaf := `{"kind":"Get","uri":"./DevInfo/DevId"}`
	if _, err := parseWindowsCSPJSON(`{"kind":"Sequence","commands":[` + strings.Repeat(leaf+",", 32) + leaf + `]}`); err == nil {
		t.Fatal("unbounded command count")
	}
	nested := leaf
	for range 5 {
		nested = `{"kind":"Atomic","commands":[` + nested + `]}`
	}
	if _, err := parseWindowsCSPJSON(nested); err == nil {
		t.Fatal("unbounded command depth")
	}
	for _, raw := range []string{
		`{"kind":"Get","uri":"./Device/Vendor/MSFT/DMClient/Provider"}`,
		`{"kind":"Get","uri":"https://example.test"}`,
		`{"kind":"Get","uri":"./Device/Vendor/MSFT/Test/../Value"}`,
		`{"kind":"Get","uri":"./Device/Vendor/MSFT/Test/Value","text":""}`,
		`{"kind":"Replace","uri":"./Device/Vendor/MSFT/Test/Value","format":"int","text":"01"}`,
		`{"kind":"Atomic","commands":[{"kind":"Get","uri":"./DevInfo/DevId"}]}`,
	} {
		spec, err := parseWindowsCSPJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := windows.PreviewCSPCommand(spec); err == nil {
			t.Fatal("compiler constraints lost in preview")
		}
	}
}

func TestWindowsCSPDraftRequestAndLifetimeBounds(t *testing.T) {
	form := url.Values{"request_key": {"11111111-1111-4111-8111-111111111111"}, "seconds": {"60"}, "command": {`{"kind":"Get","uri":"./DevInfo/DevId"}`}}
	for _, value := range []string{"60", "61", "604800"} {
		form.Set("seconds", value)
		if _, _, err := parseWindowsCSPDraft(form); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"", "0", "59", "604801", "060", "+60", "1.5", "99999999999999999999999999"} {
		form.Set("seconds", value)
		if _, _, err := parseWindowsCSPDraft(form); err == nil {
			t.Fatal("invalid lifetime admitted")
		}
	}
	form.Set("seconds", "60")
	for _, value := range []string{"", "invalid", "00000000-0000-0000-0000-000000000000", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"} {
		form.Set("request_key", value)
		if _, _, err := parseWindowsCSPDraft(form); err == nil {
			t.Fatal("invalid request identifier admitted")
		}
	}
}

func TestWindowsLargeCommandBodiesAreLimitedToExplicitCreationRoutes(t *testing.T) {
	for _, prefix := range []string{"", "/tenant/:tenant", "/tenant/:tenant/site/:site"} {
		for _, action := range []string{"/commands/preview", "/commands/create", "/commands/:command/cancel", "/commands/:command/abandon", "/updates/create", "/commands/create/extra"} {
			path := prefix + "/windows/:id" + action
			large := action == "/commands/preview" || action == "/commands/create"
			for _, size := range []int{10000, maxWindowsCSPFormBytes + 1} {
				h := &Handler{}
				e := echo.New()
				e.POST(path, func(c echo.Context) error { return c.NoContent(204) }, func(next echo.HandlerFunc) echo.HandlerFunc {
					return func(c echo.Context) error { c.Set("csrf", "expected"); return next(c) }
				}, h.WindowsCSRF)
				raw := url.Values{"csrf": {"expected"}, "command": {strings.Repeat("x", size)}}.Encode()
				r := httptest.NewRequest("POST", strings.NewReplacer(":tenant", "1", ":site", "1", ":id", "device", ":command", "command").Replace(path), strings.NewReader(raw))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if size > maxWindowsCSPFormBytes {
					r.ContentLength = -1
				}
				w := httptest.NewRecorder()
				e.ServeHTTP(w, r)
				want := 413
				if large && size < maxWindowsCSPFormBytes {
					want = 204
				}
				if w.Code != want {
					t.Fatal("body limit escaped its exact route", path, w.Code)
				}
			}
		}
	}
}

func FuzzWindowsCSPJSON(f *testing.F) {
	for _, raw := range []string{`{"kind":"Get","uri":"./DevInfo/DevId"}`, `{"kind":"Atomic","commands":[{"kind":"Replace","uri":"./Device/Vendor/MSFT/Test/Value","format":"chr","text":"\ud83d\ude00"}]}`, `{"kind":"Get","kind":"Exec"}`} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		spec, err := parseWindowsCSPJSON(raw)
		if err != nil {
			return
		}
		preview, err := windows.PreviewCSPCommand(spec)
		if err != nil {
			return
		}
		if preview.EncodedBytes > windows.MaxCSPRequestBytes {
			t.Fatal("unbounded compiled request")
		}
	})
}
