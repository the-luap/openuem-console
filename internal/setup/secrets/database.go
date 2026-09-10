package secrets

import "github.com/open-uem/nats/enrollment/servicecredentials"

// DatabaseURL reads an explicitly selected protected connection URL without
// exposing credentials through parser errors. File input is a network PostgreSQL
// URL; legacy raw inputs retain the existing driver-supported grammar.
func DatabaseURL(raw, path string) (string, error) {
	value, err := servicecredentials.DatabaseURL(raw, path)
	if err != nil {
		return "", ErrConfiguration
	}
	return value, nil
}
