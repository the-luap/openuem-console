package apple

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

var ErrRecoveryLock = errors.New("Recovery Lock management is unavailable")

const maxRecoveryLockPassword = 1024

// RecoveryLockReason requires current reported evidence. Apple currently gives
// conflicting supervision requirements; require supervision conservatively.
func (d Device) RecoveryLockReason(now time.Time) string {
	if d.Status != "enrolled" || d.Family() != PlatformMacOS || d.EnrollmentMethod != "manual_device" {
		return "Recovery Lock requires an enrolled Mac using device enrollment."
	}
	if !d.DeviceLockAllowed {
		return "This enrollment does not include device lock rights. Create a new Mac enrollment with those rights."
	}
	if !versionPattern.MatchString(d.OSVersion) || CompareVersions(d.OSVersion, "11.5") < 0 {
		return "Recovery Lock requires macOS 11.5 or later."
	}
	if d.InventoryAt == nil || d.InventoryAt.Before(now.Add(-24*time.Hour)) || d.InventoryAt.After(now) || d.SecurityAt == nil || d.SecurityAt.Before(now.Add(-24*time.Hour)) || d.SecurityAt.After(now) {
		return "Refresh device and security inventory before managing Recovery Lock."
	}
	if d.AppleSilicon == nil || !*d.AppleSilicon {
		return "Recovery Lock requires reported Apple silicon hardware."
	}
	if !d.SupervisedReported || !d.Supervised {
		return "Recovery Lock currently requires reported supervision."
	}
	management, _ := d.SecurityInventory["ManagementStatus"].(map[string]any)
	if user, _ := management["IsUserEnrollment"].(bool); user {
		return "Recovery Lock is unavailable with User Enrollment."
	}
	if !d.CertificateExpiresAt.After(now.Add(time.Minute)) {
		return "Renew the Mac management identity before managing Recovery Lock."
	}
	return ""
}

func validRecoveryLockPassword(password []byte) bool {
	if len(password) == 0 || len(password) > maxRecoveryLockPassword || !utf8.Valid(password) {
		return false
	}
	for remaining := password; len(remaining) > 0; {
		r, n := utf8.DecodeRune(remaining)
		if !(r == 9 || r == 10 || r == 13 || r >= 0x20 && r <= 0xd7ff || r >= 0xe000 && r <= 0xfffd || r >= 0x10000 && r <= 0x10ffff) {
			return false
		}
		remaining = remaining[n:]
	}
	return true
}

func newRecoveryLockPassword() ([]byte, error) {
	var random [32]byte
	defer clear(random[:])
	if _, err := rand.Read(random[:]); err != nil {
		return nil, ErrRecoveryLock
	}
	password := make([]byte, base64.RawURLEncoding.EncodedLen(len(random)))
	base64.RawURLEncoding.Encode(password, random[:])
	return password, nil
}

// Build sensitive XML from owned byte buffers without converting passwords to
// immutable Go strings or permitting caller-selected keys or command kinds.
func recoveryLockPayload(id, purpose string, previous, candidate []byte) ([]byte, string, error) {
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil || parsed.String() != id {
		return nil, "", ErrRecoveryLock
	}
	kind := "VerifyRecoveryLock"
	if purpose == "set" {
		kind = "SetRecoveryLock"
	}
	if purpose != "set" && purpose != "current" && purpose != "candidate" && purpose != "previous" {
		return nil, "", ErrRecoveryLock
	}
	if purpose == "set" {
		if (len(previous) > 0 && !validRecoveryLockPassword(previous)) || (len(candidate) > 0 && !validRecoveryLockPassword(candidate)) || (len(previous) == 0 && len(candidate) == 0) || bytes.Equal(previous, candidate) {
			return nil, "", ErrRecoveryLock
		}
	} else if len(previous) != 0 || !validRecoveryLockPassword(candidate) {
		return nil, "", ErrRecoveryLock
	}
	var out bytes.Buffer
	out.Grow(1024 + 6*(len(previous)+len(candidate)))
	out.WriteString(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CommandUUID</key><string>`)
	out.WriteString(id)
	out.WriteString(`</string><key>Command</key><dict><key>RequestType</key><string>`)
	out.WriteString(kind)
	out.WriteString(`</string>`)
	field := func(key string, value []byte) {
		out.WriteString("<key>" + key + "</key><string>")
		_ = xml.EscapeText(&out, value)
		out.WriteString("</string>")
	}
	if purpose == "set" {
		if len(previous) > 0 {
			field("CurrentPassword", previous)
		}
		field("NewPassword", candidate)
	} else {
		field("Password", candidate)
	}
	out.WriteString(`</dict></dict></plist>`)
	return out.Bytes(), kind, nil
}
