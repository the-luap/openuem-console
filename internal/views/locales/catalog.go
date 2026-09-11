package locales

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"sync"

	"github.com/invopop/ctxi18n/i18n"
	"gopkg.in/yaml.v3"
)

type catalog map[i18n.Code]*i18n.Locale

var embeddedCatalog = sync.OnceValues(func() (catalog, error) {
	return loadCatalog(Content)
})

// Load validates and loads the embedded catalogs once, before serving requests.
func Load() error {
	_, err := embeddedCatalog()
	return err
}

// WithLocale preserves the existing ordered, exact language matching and English
// fallback. The shared dictionaries are immutable after loading.
func WithLocale(ctx context.Context, accept string) (context.Context, error) {
	c, err := embeddedCatalog()
	if err != nil {
		return nil, err
	}
	return c.match(accept).WithContext(ctx), nil
}

func (c catalog) match(accept string) *i18n.Locale {
	for _, code := range i18n.ParseAcceptLanguage(accept) {
		if l := c[code]; l != nil {
			return l
		}
	}
	return c["en"]
}

func loadCatalog(src fs.FS) (catalog, error) {
	dicts := make(map[i18n.Code]*i18n.Dict)
	err := fs.WalkDir(src, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || (path.Ext(name) != ".yaml" && path.Ext(name) != ".yml" && path.Ext(name) != ".json") {
			return nil
		}
		data, err := fs.ReadFile(src, name)
		if err != nil {
			return err
		}
		// Decode strings before constructing Dict: ctxi18n v0.9.0's custom
		// JSON decoder retains escape sequences in catalog string values.
		var values map[i18n.Code]map[string]any
		if err := yaml.Unmarshal(data, &values); err != nil {
			return fmt.Errorf("decode catalog %s: %w", name, err)
		}
		for code, entries := range values {
			if err := validateEntries(entries, string(code)); err != nil {
				return fmt.Errorf("catalog %s: %w", name, err)
			}
			d := i18n.NewDict()
			for key, value := range entries {
				d.Add(key, value)
			}
			if dicts[code] == nil {
				dicts[code] = d
			} else {
				dicts[code].Merge(d)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if dicts["en"] == nil {
		return nil, fmt.Errorf("missing English fallback catalog")
	}
	out := make(catalog, len(dicts))
	for code, d := range dicts {
		if code != "en" {
			d.Merge(dicts["en"])
		}
		out[code] = i18n.NewLocale(code, d)
	}
	return out, nil
}

func validateEntries(entries map[string]any, prefix string) error {
	for key, value := range entries {
		switch v := value.(type) {
		case string:
		case map[string]any:
			if err := validateEntries(v, prefix+"."+key); err != nil {
				return err
			}
		default:
			return fmt.Errorf("translation %s.%s must be a string or mapping", prefix, key)
		}
	}
	return nil
}
