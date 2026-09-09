package apple

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"howett.net/plist"
)

func vpnCertificateProfileData(t *testing.T, scope, protocol string, broken bool) []byte {
	t.Helper()
	var root map[string]any
	if _, err := plist.Unmarshal(wifiCertificateSource(t, scope, "scep"), &root); err != nil {
		t.Fatal(err)
	}
	root["PayloadIdentifier"] = "com.example.vpn-reference." + scope + "." + protocol
	identity := root["PayloadContent"].([]any)[0].(map[string]any)
	reference := identity["PayloadUUID"]
	if broken {
		reference = uuid.NewString()
	}
	configuration := map[string]any{"RemoteAddress": "vpn.example.test", "AuthenticationMethod": "Certificate", "PayloadCertificateUUID": reference}
	vpn := map[string]any{"PayloadType": "com.apple.vpn.managed", "PayloadIdentifier": "com.example.vpn-reference.settings", "PayloadVersion": 1, "PayloadUUID": uuid.NewString(), "VPNType": protocol, "UserDefinedName": "Synthetic certificate VPN", protocol: configuration}
	if protocol == "VPN" {
		vpn["VPNSubType"] = "com.example.synthetic-provider"
	}
	if protocol == "IKEv2" {
		configuration["LocalIdentifier"], configuration["RemoteIdentifier"] = "device.example.test", "vpn.example.test"
	}
	root["PayloadContent"] = append(root["PayloadContent"].([]any), vpn)
	data, err := plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestVPNCertificateReferencesGuardUploadRevisionAndLegacyReassignment(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, _, _ := testEnrollPlatformWithKey(t, s, scope, "VPN reference Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, d)
	u := testUserEnroll(t, s, d, "alice")
	for _, channel := range []string{"System", "User"} {
		for _, protocol := range []string{"VPN", "IPSec", "IKEv2"} {
			bad := vpnCertificateProfileData(t, channel, protocol, true)
			if _, err := ParseProfile(bad); err == nil {
				t.Fatal("external VPN identity accepted on upload", channel, protocol)
			}
			p, err := s.SaveProfile(t.Context(), 1, "", 0, vpnCertificateProfileData(t, channel, protocol, false), "admin")
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
				t.Fatal("valid VPN reference rejected", channel, protocol, err)
			}
			if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, bad, "admin"); err == nil {
				t.Fatal("broken VPN reference revision accepted")
			}
			if len(revisionHistory(t, s, p.ID)) != 1 {
				t.Fatal("failed VPN revision leaked history")
			}
			var root map[string]any
			if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
				t.Fatal(err)
			}
			root["PayloadContent"].([]any)[1].(map[string]any)[protocol].(map[string]any)["PayloadCertificateUUID"] = uuid.NewString()
			bad, err = plist.Marshal(root, plist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := s.secrets.seal(bad, secretPurpose(1, p.ID, "profile"))
			if err != nil {
				t.Fatal(err)
			}
			adeExec(t, s, `UPDATE mdm_apple_profiles SET payload=$2 WHERE id=$1`, p.ID, sealed)
			if err = assign("installed"); err == nil || channel == "System" && !errors.Is(err, ErrProfilePrerequisite) {
				t.Fatal("legacy VPN reference bypassed validation", channel, protocol, err)
			}
			if err = assign("removed"); err != nil {
				t.Fatal("invalid VPN reference prevented removal", err)
			}
		}
	}
}
