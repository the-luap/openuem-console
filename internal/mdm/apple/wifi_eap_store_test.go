package apple

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"howett.net/plist"
)

func saveWiFiCertificateSource(t *testing.T, s *Store, scope, kind string) *Profile {
	t.Helper()
	var root map[string]any
	if _, err := plist.Unmarshal(wifiCertificateSource(t, scope, kind), &root); err != nil {
		t.Fatal(err)
	}
	root["PayloadIdentifier"] = "com.example.certificate." + uuid.NewString()
	data, err := plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.SaveProfile(t.Context(), 1, "", 0, data, "admin")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func wifiCompositionOptions(p *Profile) WiFiEAPTLSOptions {
	return WiFiEAPTLSOptions{Name: "Enterprise Wi-Fi", Identifier: "com.example.enterprise." + uuid.NewString(), Scope: p.Scope, SSID: "Company café", EncryptionType: "WPA2", TLSMinimum: "1.2", TLSMaximum: "1.2", ServerNames: "radius.example.test", AutoJoin: false, Hidden: true, Identity: CertificateProfileReference{ProfileID: p.ID, Revision: p.Revision}}
}

func TestWiFiCompositionUsesExactEncryptedRevisionsAndAtomicProvenance(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	for _, scope := range []string{"System", "User"} {
		identity := saveWiFiCertificateSource(t, s, scope, "scep")
		trust := saveWiFiCertificateSource(t, s, scope, "trust")
		o := wifiCompositionOptions(identity)
		o.Trust = &CertificateProfileReference{ProfileID: trust.ID, Revision: trust.Revision}
		first := revisionHistory(t, s, identity.ID)[0]
		// A retained selection stays exact after both a catalog update and deletion.
		updated := bytes.ReplaceAll(identity.Payload, []byte("synthetic-wifi-certificate-secret"), []byte("synthetic-replacement-secret"))
		if _, err := s.SaveProfile(t.Context(), 1, identity.ID, 1, updated, "admin"); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteProfile(t.Context(), 1, identity.ID, "admin"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateWiFiEAPTLSProfile(t.Context(), 1, o, "admin", nil); !errors.Is(err, access.ErrDenied) {
			t.Fatal("composition bypassed transaction authorization", err)
		}
		p, err := s.createWiFiEAPTLSProfile(t.Context(), 1, o, "admin", nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.Revision != 1 || p.Scope != scope || !bytes.Contains(p.Payload, []byte("synthetic-wifi-certificate-secret")) || bytes.Contains(p.Payload, []byte("synthetic-replacement-secret")) || !bytes.Contains(p.Payload, []byte("Source changes do not update this copy.")) {
			t.Fatal("composition substituted a source revision or lost copy provenance")
		}
		var root map[string]any
		if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
			t.Fatal(err)
		}
		if err = validateProfileCertificateReferences(root); err != nil || len(root["PayloadContent"].([]any)) != 3 {
			t.Fatal("saved composition lost local certificate bindings", err)
		}
		var audit []byte
		if err = s.db.QueryRow(`SELECT details FROM mdm_apple_audit WHERE action='apple.profile.compose' AND resource_id=$1`, p.ID).Scan(&audit); err != nil {
			t.Fatal(err)
		}
		var provenance struct {
			Sources []struct {
				Kind       string `json:"kind"`
				RevisionID string `json:"revision_id"`
				ProfileID  string `json:"profile_id"`
				Revision   int    `json:"revision"`
			} `json:"source_revisions"`
		}
		if err = json.Unmarshal(audit, &provenance); err != nil || len(provenance.Sources) != 2 || provenance.Sources[0].RevisionID != first.ID || provenance.Sources[0].ProfileID != identity.ID || provenance.Sources[0].Revision != 1 || provenance.Sources[1].ProfileID != trust.ID {
			t.Fatal("composition audit lost exact source revisions", err)
		}
		for _, query := range []string{`SELECT payload FROM mdm_apple_profiles WHERE id=$1`, `SELECT encrypted_payload FROM mdm_apple_profile_revisions WHERE profile_id=$1`} {
			var encrypted []byte
			if err = s.db.QueryRow(query, p.ID).Scan(&encrypted); err != nil || bytes.Contains(encrypted, []byte("synthetic-wifi-certificate-secret")) {
				t.Fatal("composed credentials stored in plaintext", err)
			}
		}
		var before int
		if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_profiles`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*WiFiEAPTLSOptions){
			func(v *WiFiEAPTLSOptions) { v.Identity.Revision = 999 },
			func(v *WiFiEAPTLSOptions) { v.Identity.ProfileID = uuid.NewString() },
			func(v *WiFiEAPTLSOptions) { v.Identity = *v.Trust },
			func(v *WiFiEAPTLSOptions) {
				if scope == "System" {
					v.Scope = "User"
				} else {
					v.Scope = "System"
				}
			},
			func(v *WiFiEAPTLSOptions) { v.SSID = strings.Repeat("é", 17) },
		} {
			bad := o
			bad.Identifier = "com.example.invalid." + uuid.NewString()
			change(&bad)
			if _, err = s.createWiFiEAPTLSProfile(t.Context(), 1, bad, "admin", nil); err == nil {
				t.Fatal("invalid composition saved")
			}
		}
		if _, err = s.createWiFiEAPTLSProfile(t.Context(), 2, o, "admin", nil); !errors.Is(err, ErrNotFound) {
			t.Fatal("source crossed organization", err)
		}
		adeExec(t, s, `CREATE FUNCTION reject_wifi_compose_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.profile.compose' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_wifi_compose_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_wifi_compose_audit()`)
		o.Identifier = "com.example.rollback." + uuid.NewString()
		if _, err = s.createWiFiEAPTLSProfile(t.Context(), 1, o, "admin", nil); err == nil {
			t.Fatal("audit failure accepted composition")
		}
		adeExec(t, s, `DROP TRIGGER reject_wifi_compose_audit ON mdm_apple_audit; DROP FUNCTION reject_wifi_compose_audit()`)
		var after, leaked int
		if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_profiles`).Scan(&after); err != nil || after != before {
			t.Fatal("failed composition leaked catalog state", err)
		}
		if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_profile_revisions WHERE identifier=$1`, o.Identifier).Scan(&leaked); err != nil || leaked != 0 {
			t.Fatal("audit failure leaked revision", err)
		}
		if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_audit WHERE details::text LIKE '%synthetic-wifi-certificate-secret%'`).Scan(&leaked); err != nil || leaked != 0 {
			t.Fatal("composition audit exposed credentials", err)
		}
	}
}

func wifiTLSRevision(t *testing.T, data []byte, maximum string) []byte {
	t.Helper()
	var root map[string]any
	if _, err := plist.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	root["PayloadContent"].([]any)[0].(map[string]any)["EAPClientConfiguration"].(map[string]any)["TLSMaximumVersion"] = maximum
	result, err := plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestWiFiTLSRevisionChecksAllTargetsAndPreservesRemoval(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "Enterprise Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, mac)
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "Enterprise phone", "iPhone16,1", "16.0")
	u := testUserEnroll(t, s, mac, "alice")
	for _, channel := range []string{"System", "User"} {
		adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='13.6' WHERE id=$1`, mac.ID)
		adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='16.0' WHERE id=$1`, phone.ID)
		o := wifiCompositionOptions(saveWiFiCertificateSource(t, s, channel, "scep"))
		p, err := s.createWiFiEAPTLSProfile(t.Context(), 1, o, "admin", nil)
		if err != nil {
			t.Fatal(err)
		}
		assign := func(desired string) error {
			if channel == "User" {
				return s.AssignUserProfile(t.Context(), scope, mac.ID, u.ID, p.ID, desired, "admin")
			}
			return s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID, phone.ID}, desired, "admin")
		}
		if err = assign("installed"); err != nil {
			t.Fatal(err)
		}
		changed := wifiTLSRevision(t, p.Payload, "1.3")
		if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, changed, "admin"); err == nil {
			t.Fatal("TLS 1.3 revision reached old Mac", channel)
		}
		adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='14.0' WHERE id=$1`, mac.ID)
		if channel == "System" {
			if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, changed, "admin"); !errors.Is(err, ErrProfilePrerequisite) {
				t.Fatal("TLS 1.3 revision ignored old phone", err)
			}
		}
		if len(revisionHistory(t, s, p.ID)) != 1 {
			t.Fatal("incompatible TLS revision leaked history")
		}
		stored, err := s.Profile(t.Context(), 1, p.ID)
		if err != nil || stored.Revision != 1 || stored.UUID != p.UUID {
			t.Fatal("failed TLS revision changed catalog", err)
		}
		adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='17.0' WHERE id=$1`, phone.ID)
		current, err := s.SaveProfile(t.Context(), 1, p.ID, 1, changed, "admin")
		if err != nil || current.Revision != 2 {
			t.Fatal("compatible TLS revision rejected", err)
		}
		adeExec(t, s, `UPDATE mdm_apple_devices SET os_version='13.6' WHERE id=$1`, mac.ID)
		if err = assign("installed"); err == nil {
			t.Fatal("reassignment bypassed TLS boundary")
		}
		if err = assign("removed"); err != nil {
			t.Fatal("TLS boundary prevented removal", err)
		}
	}
}

func TestWiFiCompositionPreservesACMEClientOwnershipAndMacIdentityLimits(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	phone1, _, _ := testEnrollPlatformWithKey(t, s, scope, "Enterprise first phone", "iPhone16,1", "18.0")
	phone2, _, _ := testEnrollPlatformWithKey(t, s, scope, "Enterprise second phone", "iPhone16,1", "18.0")
	o := wifiCompositionOptions(saveWiFiCertificateSource(t, s, "System", "acme"))
	p, err := s.createWiFiEAPTLSProfile(t.Context(), 1, o, "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{phone1.ID, phone2.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("copied ACME client acquired two enrollments", err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_profile_assignments WHERE profile_id=$1`, p.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed ACME batch leaked assignment", err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{phone1.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	o.Identifier = "com.example.second-copy." + uuid.NewString()
	copy, err := s.createWiFiEAPTLSProfile(t.Context(), 1, o, "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, copy.ID, []string{phone2.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("new copied payload UUID bypassed ACME ownership", err)
	}
	ad, err := s.createWiFiEAPTLSProfile(t.Context(), 1, wifiCompositionOptions(saveWiFiCertificateSource(t, s, "System", "ad")), "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, ad.ID, []string{phone2.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("Active Directory identity reached iPhone", err)
	}
}
