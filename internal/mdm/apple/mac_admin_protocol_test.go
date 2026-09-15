package apple

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/uuid"
	"howett.net/plist"
)

func TestMacAdminPasswordHashMatchesIndependentVector(t *testing.T) {
	password := []byte("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	wire, err := macAdminPasswordHashWithSalt(password, salt)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if _, err = plist.Unmarshal(wire, &root); err != nil {
		t.Fatal(err)
	}
	hash := root["SALTED-SHA512-PBKDF2"].(map[string]any)
	// Independently generated with Python hashlib.pbkdf2_hmac, SHA-512,
	// 40,000 iterations, byte values 0..31 for salt, and dklen=128.
	expected, err := hex.DecodeString("a80c80e5798fcd104fce48c084d95db40c09831db30d3d2aad01c6f5f6a5ba6d64d092428ff669afea24ef0767891abec048b4a082d4868ca61a728c75c80c34d5efc40d7768f6576aecaf856939d853fb48c64295150c019e9b2a087de404c5378a6d336814a735d32c741076103e46c1c4b3731dee587eef49e9280b32d8b4")
	if err != nil || !bytes.Equal(hash["entropy"].([]byte), expected) || !bytes.Equal(hash["salt"].([]byte), salt) || hash["iterations"] != uint64(40000) {
		t.Fatal("password hash differs from independent vector")
	}
	if bytes.Contains(wire, password) || len(root) != 1 || len(hash) != 3 {
		t.Fatal("unexpected password hash fields")
	}
	first, err := macAdminPasswordHash(password)
	if err != nil {
		t.Fatal(err)
	}
	second, err := macAdminPasswordHash(password)
	if err != nil || bytes.Equal(first, second) {
		t.Fatal("per-password random salt was reused", err)
	}
}

func TestMacAdminOptionsAndCommandBoundaries(t *testing.T) {
	o := MacAdminOptions{ShortName: "openuemadmin", FullName: "OpenUEM Administrator", PrimaryAccount: "standard", RotationDays: 30}
	for _, mutate := range []func(*MacAdminOptions){
		func(o *MacAdminOptions) { o.ShortName = "root" }, func(o *MacAdminOptions) { o.ShortName = "../admin" }, func(o *MacAdminOptions) { o.ShortName = "_daemon" }, func(o *MacAdminOptions) { o.ShortName = "Admin" }, func(o *MacAdminOptions) { o.ShortName = strings.Repeat("x", 32) }, func(o *MacAdminOptions) { o.FullName = "private\x00name" }, func(o *MacAdminOptions) { o.PrimaryAccount = "unsupported" }, func(o *MacAdminOptions) { o.RotationDays = 366 },
	} {
		v := o
		mutate(&v)
		if v.Validate() == nil {
			t.Fatal("invalid managed account options accepted")
		}
	}
	for _, password := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte("a"), 42), bytes.Repeat([]byte("a"), 44), bytes.Repeat([]byte("\x00"), 43)} {
		if _, err := macAdminPasswordHash(password); err == nil {
			t.Fatal("invalid generated password accepted")
		}
	}
	password := []byte("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")
	hash, err := macAdminPasswordHash(password)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"administrator", "standard", "skip"} {
		o.PrimaryAccount = mode
		args, err := macAdminCommandArguments("AccountConfiguration", o, "", hash)
		if err != nil {
			t.Fatal(err)
		}
		args["RequestType"] = "AccountConfiguration"
		wire, err := plist.Marshal(map[string]any{"Command": args}, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
		var root map[string]any
		if _, err = plist.Unmarshal(wire, &root); err != nil {
			t.Fatal(err)
		}
		cmd := root["Command"].(map[string]any)
		accounts := cmd["AutoSetupAdminAccounts"].([]any)
		if len(accounts) != 1 || cmd["SkipPrimarySetupAccountCreation"] != (mode == "skip") || cmd["SetPrimarySetupAccountAsRegularUser"] != (mode == "standard") {
			t.Fatal("primary account mode changed")
		}
		account := accounts[0].(map[string]any)
		if account["shortName"] != o.ShortName || !bytes.Equal(account["passwordHash"].([]byte), hash) || bytes.Contains(wire, password) {
			t.Fatal("sensitive account envelope changed")
		}
	}
	guid := strings.ToUpper(uuid.NewString())
	args, err := macAdminCommandArguments("SetAutoAdminPassword", o, guid, hash)
	if err != nil || args["GUID"] != guid || len(args) != 2 {
		t.Fatal("rotation does not bind the exact reported account", err)
	}
	for _, kind := range []string{"EraseDevice", "SetFirmwarePassword", ""} {
		if _, err = macAdminCommandArguments(kind, o, guid, hash); err == nil {
			t.Fatal("unexpected password command accepted")
		}
	}
	for _, guid := range []string{"", uuid.Nil.String(), "administrator"} {
		if _, err = macAdminCommandArguments("SetAutoAdminPassword", o, guid, hash); err == nil {
			t.Fatal("rotation accepted a non-account identity")
		}
	}
}
