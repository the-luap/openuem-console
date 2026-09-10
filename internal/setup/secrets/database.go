package secrets

import (
	"bytes"
	"net/url"
)

// DatabaseURL reads an explicitly selected protected connection URL without
// exposing credentials through parser errors. File input is a network PostgreSQL
// URL; legacy raw inputs retain the existing driver-supported grammar.
func DatabaseURL(raw, path string) (string, error) {
	if path == "" {
		if raw == "" {
			return "", ErrConfiguration
		}
		return raw, nil
	}
	if raw != "" {
		return "", ErrConfiguration
	}
	data, err := read(path, 8194)
	if err != nil {
		return "", ErrConfiguration
	}
	defer clear(data)
	value := bytes.TrimSuffix(data, []byte("\n"))
	if len(value) != len(data) {
		value = bytes.TrimSuffix(value, []byte("\r"))
	}
	if len(value) == 0 || len(value) > 8192 || bytes.ContainsFunc(value, func(r rune) bool { return r < 33 || r > 126 }) {
		return "", ErrConfiguration
	}
	parsed, err := url.Parse(string(value))
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Opaque != "" || parsed.Hostname() == "" || parsed.Fragment != "" || len(parsed.Path) < 2 {
		return "", ErrConfiguration
	}
	if _, err = url.ParseQuery(parsed.RawQuery); err != nil {
		return "", ErrConfiguration
	}
	return string(value), nil
}
