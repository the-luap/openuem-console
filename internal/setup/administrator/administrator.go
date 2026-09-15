// Package administrator initializes the first console account without emitting
// its password or persisting an account independently of its access grant.
package administrator

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/alexedwards/argon2id"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type Config struct {
	UserID       string
	PasswordFile string
}

// FromEnvironment enables protected bootstrap for the individual reference
// deployment or when an operator explicitly supplies a protected password file.
// A completed installation does not require keeping the password file mounted.
func FromEnvironment(individual bool) (*Config, error) {
	path := os.Getenv("OPENUEM_BOOTSTRAP_PASSWORD_FILE")
	if !individual && path == "" {
		return nil, nil
	}
	config := &Config{UserID: os.Getenv("OPENUEM_BOOTSTRAP_ADMIN"), PasswordFile: path}
	if config.UserID == "" {
		config.UserID = "openuem"
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}

func (config Config) Validate() error {
	alphanumeric := func(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' }
	if len(config.UserID) < 1 || len(config.UserID) > 128 || !alphanumeric(rune(config.UserID[0])) || strings.ContainsFunc(config.UserID, func(r rune) bool {
		return !(alphanumeric(r) || strings.ContainsRune("._@+-", r))
	}) {
		return errors.New("first-administrator account name is invalid")
	}
	return nil
}

func password(path string) ([]byte, error) {
	file, err := keyfile.Open(path, 130)
	if err != nil {
		return nil, errors.New("first-administrator password requires a protected regular file")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 131))
	if err != nil || len(data) > 130 {
		clear(data)
		return nil, errors.New("first-administrator password file is invalid")
	}
	value := bytes.TrimSuffix(data, []byte("\n"))
	if len(value) != len(data) {
		value = bytes.TrimSuffix(value, []byte("\r"))
	}
	if len(value) < 32 || len(value) > 128 || bytes.ContainsFunc(value, func(r rune) bool { return r < 33 || r > 126 }) {
		clear(data)
		return nil, errors.New("first-administrator password must contain 32 to 128 printable non-space ASCII characters")
	}
	return data[:len(value)], nil
}

// Initialize needs the existing Ent schema. Migration, initialization and error
// reporting never include the input file contents, password hash or SQL values.
// Existing initialized accounts, passwords and grants are left untouched.
func Initialize(ctx context.Context, db *sql.DB, config Config) (bool, error) {
	if err := config.Validate(); err != nil {
		return false, err
	}
	permissions, err := access.NewStore(db)
	if err != nil {
		return false, errors.New("first-administrator database is unavailable")
	}
	if err = permissions.Migrate(ctx); err != nil {
		return false, errors.New("first-administrator access schema is unavailable")
	}
	created, err := permissions.BootstrapNewAccount(ctx, config.UserID, func(ctx context.Context, tx *sql.Tx) error {
		secret, err := password(config.PasswordFile)
		if err != nil {
			return err
		}
		defer clear(secret)
		hash, err := argon2id.CreateHash(string(secret), argon2id.DefaultParams)
		if err != nil {
			return errors.New("first-administrator password hashing failed")
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO users(uid,name,email_verified,register,openid,passwd,use2fa,created,modified,hash,totp_secret,totp_secret_confirmed,forgot_password_code,forgot_password_code_expires_at,new_user_token)
		 VALUES($1,'OpenUEM Administrator',false,$2,false,true,false,clock_timestamp(),clock_timestamp(),$3,'',false,'',clock_timestamp(),'')`, config.UserID, openuem.REGISTER_FORCE_PASSWORD_CHANGE, hash)
		if err != nil {
			return errors.New("first-administrator account could not be created")
		}
		return nil
	})
	if err != nil {
		return false, errors.New("first-administrator initialization failed; check protected configuration and existing installation state")
	}
	return created, nil
}
