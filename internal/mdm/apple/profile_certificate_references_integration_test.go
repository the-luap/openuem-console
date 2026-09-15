package apple

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"howett.net/plist"
)

func wifiIdentityReferenceData(t *testing.T, scope string) []byte {
	t.Helper()
	settings := scepProfileSettings()
	settings["PayloadScope"] = scope
	data, err := BuildProfile("Wi-Fi client identity", "com.example.wifi-reference."+scope, "apple-scep", settings)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if _, err = plist.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	identity := root["PayloadContent"].([]any)[0].(map[string]any)
	wifi := map[string]any{"PayloadType": "com.apple.wifi.managed", "PayloadIdentifier": "com.example.wifi-reference.settings", "PayloadUUID": uuid.NewString(), "PayloadVersion": 1, "SSID_STR": "Synthetic enterprise", "EncryptionType": "WPA2", "PayloadCertificateUUID": identity["PayloadUUID"], "EAPClientConfiguration": map[string]any{"AcceptEAPTypes": []any{13}}}
	root["PayloadContent"] = append(root["PayloadContent"].([]any), wifi)
	data, err = plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func brokenWiFiIdentityReference(t *testing.T, data []byte) []byte {
	t.Helper()
	var root map[string]any
	if _, err := plist.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	root["PayloadContent"].([]any)[1].(map[string]any)["PayloadCertificateUUID"] = uuid.NewString()
	result, err := plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestCertificateReferencesRejectUploadRevisionAndLegacyReassignment(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "Wi-Fi reference Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, d)
	u := testUserEnroll(t, s, d, "alice")
	for _, channel := range []string{"System", "User"} {
		data := wifiIdentityReferenceData(t, channel)
		if _, err := ParseProfile(brokenWiFiIdentityReference(t, data)); err == nil {
			t.Fatal("cross-profile identity reference accepted on upload", channel)
		}
		p, err := s.SaveProfile(t.Context(), 1, "", 0, data, "admin")
		if err != nil {
			t.Fatal(err)
		}
		assign := func(desired string) error {
			if channel == "User" {
				return s.AssignUserProfile(t.Context(), scope, d.ID, u.ID, p.ID, desired, "admin")
			}
			return s.AssignProfile(t.Context(), scope, p.ID, []string{d.ID}, desired, "admin")
		}
		if err = assign("installed"); err != nil {
			t.Fatal("valid local identity reference rejected", channel, err)
		}
		if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, brokenWiFiIdentityReference(t, p.Payload), "admin"); err == nil {
			t.Fatal("broken reference revision accepted", channel)
		}
		if len(revisionHistory(t, s, p.ID)) != 1 {
			t.Fatal("broken reference leaked revision history")
		}
		// A pre-validation catalog row may contain a dangling reference. Refuse
		// a new install, but preserve removal of the existing assignment.
		bad := brokenWiFiIdentityReference(t, p.Payload)
		sealed, err := s.secrets.seal(bad, secretPurpose(1, p.ID, "profile"))
		if err != nil {
			t.Fatal(err)
		}
		adeExec(t, s, `UPDATE mdm_apple_profiles SET payload=$2 WHERE id=$1`, p.ID, sealed)
		if err = assign("installed"); err == nil || channel == "System" && !errors.Is(err, ErrProfilePrerequisite) {
			t.Fatal("legacy dangling identity reached an install", channel, err)
		}
		if err = assign("removed"); err != nil {
			t.Fatal("dangling identity prevented profile removal", channel, err)
		}
	}
}
