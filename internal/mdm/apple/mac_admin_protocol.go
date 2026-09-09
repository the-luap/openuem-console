package apple

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"
	"howett.net/plist"
)

var ErrMacAdmin = errors.New("managed Mac administrator action is unavailable")

// MacAdminOptions contains policy only. Every admitted Mac receives a separate
// generated password; neither passwords nor password hashes belong in a shared
// ADE profile definition or a public page model.
type MacAdminOptions struct {
	ShortName      string `json:"short_name"`
	FullName       string `json:"full_name"`
	Hidden         bool   `json:"hidden"`
	PrimaryAccount string `json:"primary_account"`
	RotationDays   int    `json:"rotation_days"`
}

var macAdminShortName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,30}$`)

func (o MacAdminOptions) Validate() error {
	if !macAdminShortName.MatchString(o.ShortName) || o.ShortName == "root" || o.ShortName == "daemon" || o.ShortName == "nobody" || len(o.FullName) > 255 || !utf8.ValidString(o.FullName) || strings.TrimSpace(o.FullName) != o.FullName || o.RotationDays < 0 || o.RotationDays > 365 {
		return ErrMacAdmin
	}
	for _, r := range o.FullName {
		if unicode.IsControl(r) || r == 0xfffe || r == 0xffff {
			return ErrMacAdmin
		}
	}
	if o.PrimaryAccount != "administrator" && o.PrimaryAccount != "standard" && o.PrimaryAccount != "skip" {
		return ErrMacAdmin
	}
	return nil
}

func validMacAdminPassword(password []byte) bool {
	if len(password) != 43 {
		return false
	}
	for _, c := range password {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func macAdminPasswordHash(password []byte) ([]byte, error) {
	var salt [32]byte
	defer clear(salt[:])
	if !validMacAdminPassword(password) {
		return nil, ErrMacAdmin
	}
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, ErrMacAdmin
	}
	return macAdminPasswordHashWithSalt(password, salt[:])
}

func macAdminPasswordHashWithSalt(password, salt []byte) ([]byte, error) {
	if !validMacAdminPassword(password) || len(salt) != 32 {
		return nil, ErrMacAdmin
	}
	// Apple documents a 32-byte salt and 20,000–40,000 iterations when the
	// hash time cannot be calibrated on the target. Its command example uses
	// 128-byte entropy. The target receives this plist as a nested data value.
	entropy := pbkdf2.Key(password, salt, 40000, 128, sha512.New)
	defer clear(entropy)
	return plist.Marshal(map[string]any{"SALTED-SHA512-PBKDF2": map[string]any{"entropy": entropy, "salt": salt, "iterations": uint64(40000)}}, plist.XMLFormat)
}

func macAdminCommandArguments(kind string, options MacAdminOptions, guid string, passwordHash []byte) (map[string]any, error) {
	if len(passwordHash) == 0 || len(passwordHash) > 4096 {
		return nil, ErrMacAdmin
	}
	switch kind {
	case "AccountConfiguration":
		if options.Validate() != nil || guid != "" {
			return nil, ErrMacAdmin
		}
		return map[string]any{"AutoSetupAdminAccounts": []any{map[string]any{"shortName": options.ShortName, "fullName": options.FullName, "hidden": options.Hidden, "passwordHash": passwordHash}}, "SkipPrimarySetupAccountCreation": options.PrimaryAccount == "skip", "SetPrimarySetupAccountAsRegularUser": options.PrimaryAccount == "standard"}, nil
	case "SetAutoAdminPassword":
		id, err := uuid.Parse(guid)
		if err != nil || id == uuid.Nil || !strings.EqualFold(id.String(), guid) {
			return nil, ErrMacAdmin
		}
		return map[string]any{"GUID": guid, "passwordHash": passwordHash}, nil
	default:
		return nil, ErrMacAdmin
	}
}
