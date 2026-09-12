package apple

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"howett.net/plist"
)

func macBindingFixture(t *testing.T) (*Store, *Device, *registry.Store) {
	t.Helper()
	s := testStore(t)
	testSettings(t, s, 1)
	r, err := registry.NewStore(s.db, "integration-test-master-key-32-bytes-minimum")
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = s.MigrateMacLinks(t.Context()); err != nil {
		t.Fatal(err)
	}
	d, _, _ := testEnrollPlatformWithKey(t, s, Scope{TenantID: 1, SiteID: 1}, "Linked Mac", "Mac16,1", "15.0")
	drainMacHardwareInventory(t, s, d, map[string]any{"SerialNumber": "ABCD123456", "ProvisioningUDID": "00006001-001234567890ABCD"})
	return s, d, r
}

func bindingCommand(t *testing.T, data []byte, kind string) (string, map[string]any) {
	t.Helper()
	var root map[string]any
	if _, err := plist.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	command, ok := root["Command"].(map[string]any)
	if !ok || stringValue(command, "RequestType") != kind {
		t.Fatal("unexpected management command")
	}
	return stringValue(root, "CommandUUID"), command
}

func TestMacBindingChallengeDeliveryCancellationCleanupAndReplacement(t *testing.T) {
	s, d, _ := macBindingFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	for range 2 {
		if err := s.RequestMacBinding(t.Context(), scope, d.ID, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_mac_bindings`).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate active challenge", err)
	}
	if err := s.RequestMacBinding(t.Context(), Scope{TenantID: 2}, d.ID, "foreign"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign scope requested verification", err)
	}
	data, err := s.Connect(t.Context(), d, map[string]any{"Status": "Idle", "UDID": d.UDID})
	if err != nil {
		t.Fatal(err)
	}
	commandID, command := bindingCommand(t, data, "InstallProfile")
	profileBytes := command["Payload"].([]byte)
	var profile map[string]any
	if _, err = plist.Unmarshal(profileBytes, &profile); err != nil {
		t.Fatal(err)
	}
	payload := profile["PayloadContent"].([]any)[0].(map[string]any)
	domain := payload["PayloadContent"].(map[string]any)[enrollment.MacBindingDomain].(map[string]any)
	values := domain["Forced"].([]any)[0].(map[string]any)["mcx_preference_settings"].(map[string]any)
	proof := enrollment.MacBindingProof{ChallengeID: stringValue(values, "ChallengeID"), DeviceID: stringValue(values, "DeviceID"), Token: stringValue(values, "Token")}
	if profile["PayloadScope"] != "System" || !proof.Valid() || proof.DeviceID != d.ID || len(values) != 3 {
		t.Fatal("managed preference proof malformed")
	}
	if _, err = ParseProfile(profileBytes); err == nil {
		t.Fatal("internal challenge entered administrator profile catalog")
	}
	var cipher []byte
	var hash string
	if err = s.db.QueryRow(`SELECT c.payload,b.token_hash FROM mdm_apple_commands c JOIN mdm_apple_mac_bindings b ON b.command_id=c.id WHERE c.id=$1`, commandID).Scan(&cipher, &hash); err != nil || bytes.Contains(cipher, []byte(proof.Token)) || hash != digest([]byte(proof.Token)) {
		t.Fatal("plaintext or incorrect proof storage", err)
	}
	if _, err = s.Connect(t.Context(), d, map[string]any{"Status": "Acknowledged", "UDID": d.UDID, "CommandUUID": commandID}); err != nil {
		t.Fatal(err)
	}
	b, err := s.MacBinding(t.Context(), scope, d.ID)
	if err != nil || b.Status != "installed" || b.InstalledAt == nil {
		t.Fatal("MDM acknowledgement did not update verification", err)
	}
	metadata, _ := json.Marshal(b)
	commands, err := s.Commands(t.Context(), scope, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	publicCommands, _ := json.Marshal(commands)
	if bytes.Contains(metadata, []byte(proof.Token)) || bytes.Contains(metadata, []byte(hash)) || bytes.Contains(publicCommands, []byte(proof.Token)) {
		t.Fatal("proof exposed in metadata")
	}
	if err = s.CancelMacBinding(t.Context(), scope, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err = s.RequestMacBinding(t.Context(), scope, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_mac_bindings`).Scan(&count); err != nil || count != 1 {
		t.Fatal("replacement bypassed pending cleanup", err)
	}
	if err = s.db.QueryRow(`SELECT payload FROM mdm_apple_commands WHERE id=$1`, commandID).Scan(&cipher); err != nil || len(cipher) != 0 {
		t.Fatal("terminal challenge retained secret command bytes", err)
	}
	data, err = s.Connect(t.Context(), d, map[string]any{"Status": "Idle", "UDID": d.UDID})
	if err != nil {
		t.Fatal(err)
	}
	cleanupID, cleanup := bindingCommand(t, data, "RemoveProfile")
	if cleanup["Identifier"] != profile["PayloadIdentifier"] {
		t.Fatal("cleanup targeted a different profile")
	}
	if _, err = s.Connect(t.Context(), d, map[string]any{"Status": "Acknowledged", "UDID": d.UDID, "CommandUUID": cleanupID}); err != nil {
		t.Fatal(err)
	}
	b, err = s.MacBinding(t.Context(), scope, d.ID)
	if err != nil || b.Status != "cancelled" || b.CleanupAt == nil {
		t.Fatal("profile cleanup acknowledgement lost", err)
	}
	if err = s.RetryCommand(t.Context(), scope, d.ID, commandID, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("terminal binding command retried", err)
	}
	if err = s.RequestMacBinding(t.Context(), scope, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	next, err := s.MacBinding(t.Context(), scope, d.ID)
	if err != nil || next.ID == b.ID || next.Status != "queued" {
		t.Fatal("fresh challenge not created after cleanup", err)
	}
	data, err = s.Connect(t.Context(), d, map[string]any{"Status": "Acknowledged", "UDID": d.UDID, "CommandUUID": cleanupID})
	if err != nil {
		t.Fatal(err)
	}
	_, newCommand := bindingCommand(t, data, "InstallProfile")
	var newProfile map[string]any
	if _, err = plist.Unmarshal(newCommand["Payload"].([]byte), &newProfile); err != nil {
		t.Fatal(err)
	}
	if newProfile["PayloadIdentifier"] == profile["PayloadIdentifier"] {
		t.Fatal("late old cleanup can remove the new proof")
	}
	// An endpoint may echo private values in its error description. Keep those
	// out of public commands and logs, even when the source is authenticated.
	if _, err = s.Connect(t.Context(), d, map[string]any{"Status": "Error", "UDID": d.UDID, "CommandUUID": next.CommandID, "ErrorChain": []any{map[string]any{"LocalizedDescription": proof.Token}}}); err != nil {
		t.Fatal(err)
	}
	commands, err = s.Commands(t.Context(), scope, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	publicCommands, _ = json.Marshal(commands)
	if bytes.Contains(publicCommands, []byte(proof.Token)) || !bytes.Contains(publicCommands, []byte("Management channel verification command failed")) {
		t.Fatal("device error exposed a proof")
	}
}

func TestMacBindingExpiryRevocationAndAuditRollback(t *testing.T) {
	for _, mode := range []string{"expiry", "revoke", "checkout", "audit", "undelivered"} {
		t.Run(mode, func(t *testing.T) {
			s, d, _ := macBindingFixture(t)
			scope := Scope{TenantID: 1, SiteID: 1}
			if mode == "audit" {
				if _, err := s.db.Exec(`ALTER TABLE mdm_apple_audit ADD CONSTRAINT binding_audit_failure CHECK(action <> 'apple.mac.binding.request') NOT VALID`); err != nil {
					t.Fatal(err)
				}
				if err := s.RequestMacBinding(t.Context(), scope, d.ID, "admin"); err == nil {
					t.Fatal("challenge committed without audit")
				}
				var n int
				if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_mac_bindings`).Scan(&n); err != nil || n != 0 {
					t.Fatal("failed audit left challenge", err)
				}
				return
			}
			if err := s.RequestMacBinding(t.Context(), scope, d.ID, "admin"); err != nil {
				t.Fatal(err)
			}
			b, err := s.MacBinding(t.Context(), scope, d.ID)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "undelivered" {
				if _, err = s.Connect(t.Context(), d, map[string]any{"Status": "Idle", "UDID": d.UDID}); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "expiry":
				if _, err = s.db.Exec(`UPDATE mdm_apple_mac_bindings SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, b.ID); err != nil {
					t.Fatal(err)
				}
				if err = s.ReconcileMacBindings(t.Context()); err != nil {
					t.Fatal(err)
				}
			case "revoke":
				if err = s.RevokeEnrollment(t.Context(), scope, d.ID, "admin"); err != nil {
					t.Fatal(err)
				}
			case "checkout":
				if err = s.CheckIn(t.Context(), d, map[string]any{"MessageType": "CheckOut", "UDID": d.UDID}); err != nil {
					t.Fatal(err)
				}
			case "undelivered":
				if err = s.CancelMacBinding(t.Context(), scope, d.ID, "admin"); err != nil {
					t.Fatal(err)
				}
			}
			b, err = s.MacBinding(t.Context(), scope, d.ID)
			if err != nil || (b.Status != "expired" && b.Status != "cancelled") {
				t.Fatal("challenge survived terminal lifecycle", err)
			}
			var size int
			if err = s.db.QueryRow(`SELECT octet_length(payload) FROM mdm_apple_commands WHERE id=$1`, b.CommandID).Scan(&size); err != nil || size != 0 {
				t.Fatal("terminal command retained secret", err)
			}
			if mode == "undelivered" && b.CleanupAt == nil {
				t.Fatal("never-delivered profile requires device cleanup")
			}
			if mode == "revoke" || mode == "checkout" {
				if b.CleanupAt != nil {
					t.Fatal("withdrawn MDM claimed profile removal")
				}
				if _, err = s.Connect(t.Context(), d, map[string]any{"Status": "Idle", "UDID": d.UDID}); !errors.Is(err, ErrUnauthorized) {
					t.Fatal("withdrawn MDM received proof", err)
				}
			}
		})
	}
}

func TestReservedManagedPreferenceDomainCannotBeUploaded(t *testing.T) {
	data, err := BuildProfile("Example", "eu.example.profile", "wifi", map[string]any{"SSID_STR": "Office", "EncryptionType": "WPA2", "Password": "synthetic-password"})
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if _, err = plist.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	payload := root["PayloadContent"].([]any)[0].(map[string]any)
	payload["PayloadType"] = "com.apple.ManagedClient.preferences"
	for _, domain := range []string{enrollment.MacBindingDomain, strings.ToUpper(enrollment.MacBindingDomain)} {
		payload["PayloadContent"] = map[string]any{domain: map[string]any{"Forced": []any{}}}
		data, err = plist.Marshal(root, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = ParseProfile(data); !errors.Is(err, ErrMacBinding) {
			t.Fatal("reserved managed domain uploaded", err)
		}
	}
}

func TestMacBindingCleanupRetriesAreBoundedAndRetainInternalClassification(t *testing.T) {
	s, d, _ := macBindingFixture(t)
	scope := Scope{TenantID: 1, SiteID: 1}
	deliverMacProof(t, s, d)
	if err := s.CancelMacBinding(t.Context(), scope, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	var prior string
	for attempt := 1; attempt <= 6; attempt++ {
		b, err := s.MacBinding(t.Context(), scope, d.ID)
		want := attempt
		if attempt == 6 {
			want = 1 // Explicit administrator retry starts a new bounded cycle.
		}
		if err != nil || b.CleanupAttempts != want || b.CleanupRetryable() || b.CleanupStatus != "queued" {
			t.Fatal("pending cleanup exposed retry or lost attempt", b, err)
		}
		if err = s.RequestMacBinding(t.Context(), scope, d.ID, "admin"); err != nil {
			t.Fatal(err)
		}
		data, err := s.Connect(t.Context(), d, map[string]any{"Status": "Idle", "UDID": d.UDID})
		if err != nil {
			t.Fatal(err)
		}
		command, _ := bindingCommand(t, data, "RemoveProfile")
		if command == prior {
			t.Fatal("failed cleanup command was reused")
		}
		prior = command
		if _, err = s.Connect(t.Context(), d, map[string]any{"Status": "Error", "UDID": d.UDID, "CommandUUID": command, "ErrorChain": []any{map[string]any{"LocalizedDescription": "synthetic-sensitive-error"}}}); err != nil {
			t.Fatal(err)
		}
		b, err = s.MacBinding(t.Context(), scope, d.ID)
		if err != nil || !b.CleanupRetryable() || b.CleanupStatus != "failed" || b.CleanupAttempts != want {
			t.Fatal("failed cleanup cannot be deliberately retried", b, err)
		}
		if attempt == 5 {
			if _, err = s.db.Exec(`UPDATE mdm_apple_mac_bindings SET next_cleanup_at=clock_timestamp() WHERE device_id=$1`, d.ID); err != nil {
				t.Fatal(err)
			}
		}
		if err = s.ReconcileMacBindings(t.Context()); err != nil {
			t.Fatal(err)
		}
		after, err := s.MacBinding(t.Context(), scope, d.ID)
		if err != nil || after.CleanupAttempts != want || after.CleanupStatus != "failed" {
			t.Fatal("automatic cleanup exceeded backoff or attempt bound", after, err)
		}
		if err = s.RequestMacBinding(t.Context(), scope, d.ID, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	commands, err := s.Commands(t.Context(), scope, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		if command.RequestType == "RemoveProfile" {
			if !command.MacBinding || command.Error == "synthetic-sensitive-error" {
				t.Fatal("historical cleanup command lost redaction classification")
			}
			if err = s.RetryCommand(t.Context(), scope, d.ID, command.ID, "admin"); err == nil {
				t.Fatal("internal cleanup entered generic retry")
			}
		}
	}
	acknowledgeMacCleanup(t, s, d)
	b, err := s.MacBinding(t.Context(), scope, d.ID)
	if err != nil || b.CleanupAt == nil || b.CleanupRetryable() {
		t.Fatal("successful retry did not finish cleanup", err)
	}
}
