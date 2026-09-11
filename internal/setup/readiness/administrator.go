package readiness

import (
	"context"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/open-uem/nats/enrollment/servicecredentials"
	"github.com/open-uem/openuem-console/internal/setup/administrator"
	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

func administratorCheck(ctx context.Context, options Options) (func() bool, func(), error) {
	config := administrator.Config{UserID: options.Administrator, PasswordFile: options.InitialPasswordFile}
	if options.Address != "" || options.Origin != "" || options.TrustFile != "" || options.KeyFile != "" || config.Validate() != nil || options.Installation == "" {
		return nil, nil, ErrConfiguration
	}
	for _, path := range []string{options.DatabaseURLFile, options.InitialPasswordFile, options.JWTFile, options.MasterFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, nil, ErrConfiguration
		}
	}
	credentials, err := secrets.Load(secrets.Inputs{Installation: options.Installation, JWTFile: options.JWTFile, MasterFile: options.MasterFile, Required: true})
	if err != nil {
		return nil, nil, ErrConfiguration
	}
	dsn, err := servicecredentials.DatabaseURL("", options.DatabaseURLFile)
	if err != nil {
		return nil, nil, ErrConfiguration
	}
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Hostname() == "" || parsed.Port() == "" || parsed.User == nil || parsed.User.Username() == "" || parsed.Fragment != "" || strings.TrimPrefix(parsed.Path, "/") == "" {
		return nil, nil, ErrConfiguration
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(query) != 2 || len(query["sslmode"]) != 1 || query.Get("sslmode") != "verify-full" || len(query["sslrootcert"]) != 1 || !filepath.IsAbs(query.Get("sslrootcert")) || filepath.Clean(query.Get("sslrootcert")) != query.Get("sslrootcert") {
		return nil, nil, ErrConfiguration
	}
	password, present := parsed.User.Password()
	connection, err := pgx.ParseConfig(dsn)
	if err != nil || !present || password == "" || connection.Host != parsed.Hostname() || connection.Database != strings.TrimPrefix(parsed.Path, "/") || connection.TLSConfig == nil || connection.TLSConfig.InsecureSkipVerify || connection.TLSConfig.ServerName != parsed.Hostname() {
		return nil, nil, ErrConfiguration
	}
	// Use only the explicit deployment URL and its public TLS trust, without
	// environment-selected client identities, fallback hosts or search paths.
	connection.Fallbacks = nil
	connection.RuntimeParams = map[string]string{"search_path": "public"}
	connection.TLSConfig.Certificates = nil
	connection.TLSConfig.GetClientCertificate = nil
	db := stdlib.OpenDB(*connection)
	db.SetMaxOpenConns(1)
	return func() bool { return administrator.CheckCompletion(ctx, db, config, credentials) == nil }, func() { db.Close() }, nil
}
