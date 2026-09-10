package common

import (
	"os"

	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

func installedDatabaseURL(legacy func() (string, error)) (string, error) {
	if path := os.Getenv("DATABASE_URL_FILE"); path != "" {
		return secrets.DatabaseURL(os.Getenv("DATABASE_URL"), path)
	}
	value, err := legacy()
	if err != nil {
		return "", err
	}
	return secrets.DatabaseURL(value, "")
}

// A mounted JWT file makes the legacy INI/credential-store lookup unnecessary.
// Explicit raw environment input alongside that file is still ambiguous.
func installedSecrets(required bool, legacyJWT func() (string, error)) (secrets.Runtime, error) {
	jwt := os.Getenv("JWT_KEY")
	if os.Getenv("JWT_KEY_FILE") == "" {
		var err error
		jwt, err = legacyJWT()
		if err != nil {
			return secrets.Runtime{}, err
		}
	}
	return secrets.Load(secrets.Inputs{Installation: os.Getenv("OPENUEM_INSTALLATION_ID"), JWT: jwt, Master: os.Getenv("ENCRYPTION_MASTER_KEY"), JWTFile: os.Getenv("JWT_KEY_FILE"), MasterFile: os.Getenv("ENCRYPTION_MASTER_KEY_FILE"), Required: required})
}
