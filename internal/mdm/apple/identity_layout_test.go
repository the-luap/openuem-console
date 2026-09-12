package apple

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestEnrollmentLayoutRecoveryRejectsAmbiguousInventory(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	d, _ := testEnroll(t, s, Scope{TenantID: 1, SiteID: 1}, "Layout recovery")
	if _, err := s.db.Exec(`DELETE FROM mdm_apple_enrollment_layouts WHERE device_id=$1`, d.ID); err != nil {
		t.Fatal(err)
	}
	prefix := "eu.openuem.enrollment." + d.ID
	for _, name := range []string{"valid", "missing payload UUID", "duplicate payload", "empty duplicate", "extra payload", "wrong type", "duplicate profile", "repeated UUID", "invalid UUID"} {
		t.Run(name, func(t *testing.T) {
			profile := InstalledProfile{Identifier: prefix, UUID: strings.ToUpper(uuid.NewString()), Payloads: []InstalledPayload{{Identifier: prefix + ".mdm", UUID: strings.ToUpper(uuid.NewString()), Type: "com.apple.mdm"}, {Identifier: prefix + ".identity", UUID: strings.ToUpper(uuid.NewString()), Type: "com.apple.security.pkcs12"}}}
			switch name {
			case "missing payload UUID":
				profile.Payloads[0].UUID = ""
			case "duplicate payload":
				profile.Payloads = append(profile.Payloads, profile.Payloads[0])
			case "empty duplicate":
				profile.Payloads = append(profile.Payloads, profile.Payloads[0])
				profile.Payloads[0].UUID = ""
			case "extra payload":
				profile.Payloads = append(profile.Payloads, InstalledPayload{Identifier: prefix + ".wifi", UUID: uuid.NewString(), Type: "com.apple.wifi.managed"})
			case "wrong type":
				profile.Payloads[1].Type = "com.apple.security.root"
			case "repeated UUID":
				profile.Payloads[1].UUID = profile.Payloads[0].UUID
			case "invalid UUID":
				profile.UUID = "invalid"
			}
			profiles := []InstalledProfile{profile}
			if name == "duplicate profile" {
				profiles = append(profiles, profile)
			}
			tx, err := s.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err = s.recoverEnrollmentLayout(context.Background(), tx, d, profiles); err != nil {
				t.Fatal(err)
			}
			var count int
			if err = tx.QueryRow(`SELECT count(*) FROM mdm_apple_enrollment_layouts WHERE device_id=$1`, d.ID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if (name == "valid" && count != 1) || (name != "valid" && count != 0) {
				t.Fatal("unsafe enrollment metadata recovery", count)
			}
			if name == "valid" {
				layout, err := loadEnrollmentLayout(context.Background(), tx, d.ID)
				if err != nil || layout.profileUUID != profile.UUID || layout.mdmUUID != profile.Payloads[0].UUID || layout.caUUID != "" {
					t.Fatal("recovery changed reported UUID casing or invented an old root", err)
				}
			}
		})
	}
}
