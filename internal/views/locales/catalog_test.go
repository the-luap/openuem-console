package locales

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/invopop/ctxi18n/i18n"
)

func TestCatalogDecodesStringsBeforeInterpolation(t *testing.T) {
	values := map[string]any{
		"ampersand": "Apple setup & enrollment",
		"quotes":    `The "quoted" report`,
		"lines":     "first\nsecond\tcolumn\rreturn",
		"literal":   `C:\new\tools\u0026`,
		"markup":    `<img src=x onerror="window.catalogCanary=true"> & text`,
		"unicode":   "Größe – 日本語 \u2028 \u2029",
		"named":     "Value: %{value}",
		"formatted": "Value: %s",
		"nested":    map[string]any{"fallback": "English & fallback", "translated": "English"},
		"count":     map[string]any{"one": "One & only", "other": "%d & more"},
	}
	data, err := json.Marshal(map[string]any{"en": values})
	if err != nil {
		t.Fatal(err)
	}
	c, err := loadCatalog(fstest.MapFS{
		"en.json": {Data: data},
		"de.yaml": {Data: []byte("de:\n  nested:\n    translated: 'Deutsch & lokal'\n  quoted: \"A \\\"quote\\\"\\nnext\"\n  literal: 'C:\\new\\tools\\u0026'\n")},
	})
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range values {
		want, ok := value.(string)
		if !ok {
			continue
		}
		for _, code := range []i18n.Code{"en", "de"} {
			if got := c[code].T(key); got != want {
				t.Errorf("%s.%s = %q, want %q", code, key, got, want)
			}
		}
	}
	for key, want := range map[string]string{"nested.translated": "Deutsch & lokal", "nested.fallback": "English & fallback", "quoted": "A \"quote\"\nnext", "literal": `C:\new\tools\u0026`} {
		if got := c["de"].T(key); got != want {
			t.Errorf("de.%s = %q, want %q", key, got, want)
		}
	}
	argument := `<script>\u0026\n"quoted"</script>`
	ctx := c["de"].WithContext(context.Background())
	if got := i18n.T(ctx, "named", i18n.M{"value": argument}); got != "Value: "+argument {
		t.Fatalf("named interpolation changed input: %q", got)
	}
	if got := i18n.T(ctx, "formatted", argument); got != "Value: "+argument {
		t.Fatalf("formatted interpolation changed input: %q", got)
	}
	if got := i18n.N(ctx, "count", 1); got != "One & only" {
		t.Fatalf("singular fallback = %q", got)
	}
	if got := i18n.N(ctx, "count", 2, 2); got != "2 & more" {
		t.Fatalf("plural fallback = %q", got)
	}
}

func TestCatalogRejectsInvalidFiles(t *testing.T) {
	for name, data := range map[string]string{
		"missing fallback": "de:\n  value: Text\n",
		"malformed":        "en: [",
		"number":           "en:\n  value: 42\n",
		"list":             "en:\n  value: [a, b]\n",
		"nested null":      "en:\n  nested:\n    value: null\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadCatalog(fstest.MapFS{"catalog.yaml": {Data: []byte(data)}}); err == nil {
				t.Fatal("invalid catalog accepted")
			}
		})
	}
}

func TestEmbeddedCatalogsAreConcurrentAndKeepLanguageSelection(t *testing.T) {
	for n := 0; n < 64; n++ {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			t.Parallel()
			if err := Load(); err != nil {
				t.Fatal(err)
			}
			for accept, want := range map[string]string{
				"": "en", "unknown": "en", "en": "en", "de": "de", "es": "es",
				"fr": "fr", "ca": "ca", "pt": "pt", "no": "no",
				"de-DE,de;q=0.9,en;q=0.8": "de", "unknown, fr;q=0.8": "fr",
			} {
				ctx, err := WithLocale(context.Background(), accept)
				if err != nil {
					t.Fatal(err)
				}
				if got := i18n.GetLocale(ctx).Code().String(); got != want {
					t.Errorf("match %q = %q, want %q", accept, got, want)
				}
				if got := i18n.T(ctx, "management_navigation.apple_enrollment"); got != "Apple setup & enrollment" {
					t.Errorf("catalog fallback retained escapes: %q", got)
				}
				if got := i18n.T(ctx, "management_navigation.title"); strings.Contains(got, "MISSING") {
					t.Errorf("missing catalog key: %q", got)
				}
			}
		})
	}
}
