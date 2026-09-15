package apple

import (
	"testing"

	"github.com/google/uuid"
	"howett.net/plist"
)

func alwaysOnCertificateProfileData(t *testing.T, group int, broken bool) []byte {
	t.Helper()
	var root map[string]any
	if _, err := plist.Unmarshal(vpnCertificateProfileData(t, "System", "IKEv2", "com.apple.vpn.managed", false), &root); err != nil {
		t.Fatal(err)
	}
	root["PayloadIdentifier"] = "com.example.always-on-certificates"
	vpn := root["PayloadContent"].([]any)[1].(map[string]any)
	tunnel := vpn["IKEv2"].(map[string]any)
	delete(vpn, "IKEv2")
	tunnel["ProtocolType"], tunnel["Interfaces"] = "IKEv2", []any{"WiFi"}
	tunnel["IKESecurityAssociationParameters"] = map[string]any{"DiffieHellmanGroup": group}
	second := map[string]any{}
	for key, value := range tunnel {
		second[key] = value
	}
	second["Interfaces"] = []any{"Cellular"}
	if broken {
		second["PayloadCertificateUUID"] = uuid.NewString()
	}
	vpn["VPNType"] = "AlwaysOn"
	vpn["AlwaysOn"] = map[string]any{"UIToggleEnabled": 0, "TunnelConfigurations": []any{tunnel, second}}
	data, err := plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestAlwaysOnTunnelReferencesAndAlgorithmRestorationAreTransactional(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "Always On certificate phone", "iPhone16,1", "18.0")
	adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='14.1',supervised=true,supervised_reported=true,inventory_at=clock_timestamp() WHERE id=$1`, phone.ID)
	if _, err := s.SaveProfile(t.Context(), 1, "", 0, alwaysOnCertificateProfileData(t, 14, true), "admin"); err == nil {
		t.Fatal("dangling second tunnel identity accepted on upload")
	}
	p, err := s.SaveProfile(t.Context(), 1, "", 0, alwaysOnCertificateProfileData(t, 5, false), "admin")
	if err != nil {
		t.Fatal(err)
	}
	assign := func(desired string) error {
		return s.AssignProfile(t.Context(), scope, p.ID, []string{phone.ID}, desired, "admin")
	}
	if err = assign("installed"); err != nil {
		t.Fatal(err)
	}
	first := revisionHistory(t, s, p.ID)[0]
	adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='14.2' WHERE id=$1`, phone.ID)
	if err = assign("installed"); err == nil {
		t.Fatal("Always On DH limitation bypassed on reassignment")
	}
	if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, alwaysOnCertificateProfileData(t, 14, true), "admin"); err == nil {
		t.Fatal("dangling second tunnel identity accepted on revision")
	}
	if len(revisionHistory(t, s, p.ID)) != 1 {
		t.Fatal("invalid Always On identity revision leaked history")
	}
	modern, err := s.SaveProfile(t.Context(), 1, p.ID, 1, alwaysOnCertificateProfileData(t, 14, false), "admin")
	if err != nil {
		t.Fatal("Always On DH replacement failed", err)
	}
	var before, after int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1`, p.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err = s.restoreProfileRevision(t.Context(), 1, p.ID, first.ID, 2, "Synthetic small-group restoration check", "admin", nil); err == nil {
		t.Fatal("Always On restoration ignored DH limitation")
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1`, p.ID).Scan(&after); err != nil || after != before || len(revisionHistory(t, s, p.ID)) != 2 {
		t.Fatal("failed Always On restore changed commands or history", err)
	}
	stored, err := s.Profile(t.Context(), 1, p.ID)
	if err != nil || stored.UUID != modern.UUID || stored.Revision != 2 {
		t.Fatal("failed Always On restore changed catalog", err)
	}
	var root map[string]any
	if _, err = plist.Unmarshal(modern.Payload, &root); err != nil {
		t.Fatal(err)
	}
	root["PayloadContent"].([]any)[1].(map[string]any)["AlwaysOn"].(map[string]any)["TunnelConfigurations"].([]any)[1].(map[string]any)["PayloadCertificateUUID"] = uuid.NewString()
	bad, err := plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.secrets.seal(bad, secretPurpose(1, p.ID, "profile"))
	if err != nil {
		t.Fatal(err)
	}
	adeExec(t, s, `UPDATE mdm_apple_profiles SET payload=$2 WHERE id=$1`, p.ID, sealed)
	if err = assign("installed"); err == nil {
		t.Fatal("legacy second tunnel reference bypassed validation")
	}
	if err = assign("removed"); err != nil {
		t.Fatal("legacy Always On identity prevented removal", err)
	}
}
