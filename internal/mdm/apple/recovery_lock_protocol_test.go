package apple

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"howett.net/plist"
)

func TestRecoveryLockPayloadPreservesPasswordsAndRestrictsCommands(t *testing.T) {
	id := uuid.NewString()
	password := []byte(" <&\"'\t\r\n日本語🔐 ")
	for _, tc := range []struct {
		purpose   string
		old, next []byte
	}{
		{"set", nil, password}, {"set", password, []byte("replacement")}, {"set", password, nil},
		{"current", nil, password}, {"candidate", nil, password}, {"previous", nil, password},
	} {
		t.Run(tc.purpose, func(t *testing.T) {
			old, next := bytes.Clone(tc.old), bytes.Clone(tc.next)
			payload, kind, err := recoveryLockPayload(id, tc.purpose, tc.old, tc.next)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(payload)
			var wire struct {
				ID      string `plist:"CommandUUID"`
				Command map[string]any
			}
			if _, err = plist.Unmarshal(payload, &wire); err != nil {
				t.Fatal(err)
			}
			if wire.ID != id || wire.Command["RequestType"] != kind {
				t.Fatal("incorrect command envelope")
			}
			if tc.purpose == "set" {
				if kind != "SetRecoveryLock" || wire.Command["NewPassword"] != string(next) {
					t.Fatal("new password changed")
				}
				value, exists := wire.Command["CurrentPassword"]
				if exists != (len(old) > 0) || (exists && value != string(old)) {
					t.Fatal("current password changed")
				}
			} else if kind != "VerifyRecoveryLock" || len(wire.Command) != 2 || wire.Command["Password"] != string(next) {
				t.Fatal("verification changed password or gained mutation fields")
			}
			if !bytes.Equal(old, tc.old) || !bytes.Equal(next, tc.next) {
				t.Fatal("caller buffer changed")
			}
		})
	}
	for _, tc := range []struct {
		id, purpose string
		old, next   []byte
	}{
		{"bad", "set", nil, password}, {uuid.Nil.String(), "set", nil, password},
		{strings.ToUpper("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), "set", nil, password},
		{id, "EraseDevice", nil, password}, {id, "set", nil, nil}, {id, "set", password, password},
		{id, "candidate", password, password}, {id, "candidate", nil, nil},
		{id, "set", []byte{0}, password}, {id, "set", nil, []byte{0xff}},
	} {
		if payload, _, err := recoveryLockPayload(tc.id, tc.purpose, tc.old, tc.next); err == nil || len(payload) > 0 {
			t.Fatal("invalid sensitive command accepted")
		}
	}
}

func TestRecoveryLockPasswordValidationAndGeneration(t *testing.T) {
	for _, tc := range []struct {
		password []byte
		valid    bool
	}{
		{nil, false}, {[]byte(" "), true}, {[]byte("\t\r\n"), true}, {[]byte{0}, false}, {[]byte{0x1f}, false},
		{[]byte{0xff}, false}, {[]byte("\ufffe"), false}, {[]byte("🔐日本語"), true},
		{bytes.Repeat([]byte("a"), 1024), true}, {bytes.Repeat([]byte("a"), 1025), false}, {bytes.Repeat([]byte("é"), 513), false},
	} {
		if validRecoveryLockPassword(tc.password) != tc.valid {
			t.Fatal("incorrect password boundary")
		}
	}
	seen := map[string]bool{}
	for range 100 {
		password, err := newRecoveryLockPassword()
		if err != nil || len(password) != 43 || !validRecoveryLockPassword(password) || seen[string(password)] {
			t.Fatal("invalid or reused generated password", err)
		}
		seen[string(password)] = true
		clear(password)
	}
}

func TestRecoveryLockRequiresFreshNativeAuthority(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-time.Minute)
	old := now.Add(-25 * time.Hour)
	future := now.Add(time.Minute)
	yes, no := true, false
	base := Device{Status: "enrolled", OSFamily: PlatformMacOS, Model: "Mac16,1", OSVersion: "15.0", EnrollmentMethod: "manual_device", DeviceLockAllowed: true, InventoryAt: &fresh, SecurityAt: &fresh, AppleSilicon: &yes, Supervised: true, SupervisedReported: true, CertificateExpiresAt: now.Add(time.Hour)}
	if reason := base.RecoveryLockReason(now); reason != "" {
		t.Fatal(reason)
	}
	for name, mutate := range map[string]func(*Device){
		"revoked": func(d *Device) { d.Status = "revoked" }, "phone": func(d *Device) { d.OSFamily = PlatformIOS; d.Model = "iPhone16,1" },
		"user channel": func(d *Device) { d.EnrollmentMethod = "user" }, "rights": func(d *Device) { d.DeviceLockAllowed = false },
		"malformed OS": func(d *Device) { d.OSVersion = "15garbage" },
		"old OS":       func(d *Device) { d.OSVersion = "11.4" }, "missing OS": func(d *Device) { d.OSVersion = "" },
		"missing inventory": func(d *Device) { d.InventoryAt = nil }, "old inventory": func(d *Device) { d.InventoryAt = &old }, "future inventory": func(d *Device) { d.InventoryAt = &future },
		"missing security": func(d *Device) { d.SecurityAt = nil }, "old security": func(d *Device) { d.SecurityAt = &old }, "future security": func(d *Device) { d.SecurityAt = &future },
		"unknown hardware": func(d *Device) { d.AppleSilicon = nil }, "Intel": func(d *Device) { d.AppleSilicon = &no },
		"unsupervised": func(d *Device) { d.Supervised = false }, "unreported supervision": func(d *Device) { d.SupervisedReported = false },
		"user enrollment": func(d *Device) {
			d.SecurityInventory = map[string]any{"ManagementStatus": map[string]any{"IsUserEnrollment": true}}
		},
		"short identity": func(d *Device) { d.CertificateExpiresAt = now.Add(time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			d := base
			mutate(&d)
			if d.RecoveryLockReason(now) == "" {
				t.Fatal("unready Mac accepted")
			}
		})
	}
}
