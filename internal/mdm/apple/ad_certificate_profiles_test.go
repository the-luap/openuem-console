package apple

import (
	"errors"
	"testing"

	"howett.net/plist"
)

func adCertificateProfileData(t *testing.T, identifier, scope string, settings map[string]any) []byte {
	t.Helper()
	settings["PayloadScope"] = scope
	data, err := BuildProfile("Directory certificate", identifier, "apple-ad-certificate", settings)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestADCertificateRevisionsValidateSystemAndUserTargetsAndKeepRemoval(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "Directory certificate Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, mac)
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "Directory certificate phone", "iPhone16,1", "18.0")
	u := testUserEnroll(t, s, mac, "alice")
	for _, channel := range []string{"System", "User"} {
		adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='10.9' WHERE id=$1`, mac.ID)
		settings := adCertificateSettings()
		p, err := s.SaveProfile(t.Context(), 1, "", 0, adCertificateProfileData(t, "com.example.ad-certificate."+channel, channel, settings), "admin")
		if err != nil {
			t.Fatal(err)
		}
		assign := func(desired string) error {
			if channel == "User" {
				return s.AssignUserProfile(t.Context(), scope, mac.ID, u.ID, p.ID, desired, "admin")
			}
			return s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID}, desired, "admin")
		}
		if err = assign("installed"); err != nil {
			t.Fatal(err)
		}
		if err = s.AssignProfile(t.Context(), scope, p.ID, []string{phone.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
			t.Fatal("AD certificate reached phone", err)
		}
		settings["KeyIsExtractable"] = false
		changed := adCertificateProfileData(t, p.Identifier, channel, settings)
		if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, changed, "admin"); err == nil {
			t.Fatal("explicit AD key setting reached old Mac", channel)
		}
		if len(revisionHistory(t, s, p.ID)) != 1 {
			t.Fatal("unsupported AD revision leaked history")
		}
		stored, err := s.Profile(t.Context(), 1, p.ID)
		if err != nil || stored.UUID != p.UUID || stored.Revision != 1 {
			t.Fatal("unsupported AD revision changed catalog", err)
		}
		adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='10.10' WHERE id=$1`, mac.ID)
		if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, changed, "admin"); err != nil {
			t.Fatal(err)
		}
		settings["EnableAutoRenewal"] = channel == "System"
		changed = adCertificateProfileData(t, p.Identifier, channel, settings)
		adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='10.13.3' WHERE id=$1`, mac.ID)
		if _, err = s.SaveProfile(t.Context(), 1, p.ID, 2, changed, "admin"); err == nil {
			t.Fatal("AD renewal option reached older OS", channel)
		}
		if len(revisionHistory(t, s, p.ID)) != 2 {
			t.Fatal("unsupported AD renewal revision leaked history")
		}
		adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='10.13.4' WHERE id=$1`, mac.ID)
		if _, err = s.SaveProfile(t.Context(), 1, p.ID, 2, changed, "admin"); err != nil {
			t.Fatal(err)
		}
		adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='10.13.3' WHERE id=$1`, mac.ID)
		if err = assign("installed"); err == nil {
			t.Fatal("AD reassignment skipped property version check")
		}
		if err = assign("removed"); err != nil {
			t.Fatal("AD version check prevented removal", err)
		}
	}
}

func TestADCertificateInvalidArchiveAndCompositionAreRejected(t *testing.T) {
	settings := adCertificateSettings()
	data := adCertificateProfileData(t, "com.example.ad-certificate", "System", settings)
	var root map[string]any
	if _, err := plist.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	root["PayloadContent"].([]any)[0].(map[string]any)["AllowAllAppsAccess"] = "false"
	bad, err := plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseProfile(bad); err == nil {
		t.Fatal("invalid uploaded AD switch accepted")
	}
	wifi := wifiEAPSettings(t, "System", "scep")
	wifi["IdentityProfileData"] = bad
	if _, err = BuildProfile("Enterprise Wi-Fi", "com.example.ad-wifi", "wifi-eap-tls", wifi); err == nil {
		t.Fatal("composition bypassed AD payload validation")
	}
}
