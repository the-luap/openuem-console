package apple

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"
	"howett.net/plist"
)

func buildIKEv2CertificateProfileData(t *testing.T, scope, kind, mode string) []byte {
	t.Helper()
	settings := ikev2CertificateSettings(t, scope, kind, mode)
	settings["PayloadScope"] = scope
	data, err := BuildProfile("Certificate VPN", "com.example.ikev2-certificate."+uuid.NewString(), "vpn-ikev2-certificate", settings)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestIKEv2CertificateBuilderPersistsEncryptedProfilesForBothChannels(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "Certificate VPN Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, mac)
	u := testUserEnroll(t, s, mac, "alice")
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "Certificate VPN phone", "iPhone16,1", "18.0")
	for _, channel := range []string{"System", "User"} {
		for _, mode := range []string{"machine", "eap-tls"} {
			data := buildIKEv2CertificateProfileData(t, channel, "scep", mode)
			p, err := s.SaveProfile(t.Context(), 1, "", 0, data, "admin")
			if err != nil {
				t.Fatal(err)
			}
			if p.Scope != channel || !bytes.Contains(p.Payload, []byte("synthetic-wifi-certificate-secret")) {
				t.Fatal("VPN composition lost source credentials or channel")
			}
			var root map[string]any
			if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
				t.Fatal(err)
			}
			if err = validateProfileCertificateReferences(root); err != nil {
				t.Fatal(err)
			}
			for _, query := range []string{`SELECT payload FROM mdm_apple_profiles WHERE id=$1`, `SELECT encrypted_payload FROM mdm_apple_profile_revisions WHERE profile_id=$1`} {
				var encrypted []byte
				if err = s.db.QueryRow(query, p.ID).Scan(&encrypted); err != nil || bytes.Contains(encrypted, []byte("synthetic-wifi-certificate-secret")) {
					t.Fatal("VPN composition was stored in plaintext", err)
				}
			}
			if channel == "System" {
				err = s.AssignProfile(t.Context(), scope, p.ID, []string{mac.ID, phone.ID}, "installed", "admin")
			} else {
				err = s.AssignUserProfile(t.Context(), scope, mac.ID, u.ID, p.ID, "installed", "admin")
			}
			if err != nil {
				t.Fatal("valid certificate VPN rejected", channel, mode, err)
			}
		}
	}
}

func TestIKEv2CertificateCopiesPreserveACMEOwnershipAndADTargetRules(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	first, _, _ := testEnrollPlatformWithKey(t, s, scope, "First VPN phone", "iPhone16,1", "18.0")
	second, _, _ := testEnrollPlatformWithKey(t, s, scope, "Second VPN phone", "iPhone16,2", "18.0")
	data := buildIKEv2CertificateProfileData(t, "System", "acme", "eap-tls")
	p, err := s.SaveProfile(t.Context(), 1, "", 0, data, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, p.ID, []string{first.ID}, "installed", "admin"); err != nil {
		t.Fatal(err)
	}
	copyData := buildIKEv2CertificateProfileData(t, "System", "acme", "eap-tls")
	copy, err := s.SaveProfile(t.Context(), 1, "", 0, copyData, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, copy.ID, []string{second.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("fresh VPN copy bypassed ACME client ownership", err)
	}
	ad, err := s.SaveProfile(t.Context(), 1, "", 0, buildIKEv2CertificateProfileData(t, "System", "ad", "machine"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AssignProfile(t.Context(), scope, ad.ID, []string{first.ID}, "installed", "admin"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("VPN copy allowed AD identity on a phone", err)
	}
}
