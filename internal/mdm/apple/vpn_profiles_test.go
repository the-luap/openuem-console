package apple

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"howett.net/plist"
)

func vpnConfigurationProfileData(t *testing.T, scope, identifier string, payload map[string]any) []byte {
	t.Helper()
	payload["PayloadIdentifier"], payload["PayloadUUID"], payload["PayloadVersion"] = identifier+".settings", uuid.NewString(), 1
	root := map[string]any{"PayloadType": "Configuration", "PayloadIdentifier": identifier, "PayloadUUID": uuid.NewString(), "PayloadVersion": 1, "PayloadScope": scope, "PayloadContent": []any{payload}}
	data, err := plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestVPNTargetsGuardSystemAndUserRevisionTransactions(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "VPN revision Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, mac)
	u := testUserEnroll(t, s, mac, "alice")
	for _, channel := range []string{"System", "User"} {
		for _, feature := range []string{"TransparentProxy", "DNS"} {
			below, at := "13.6", "14.0"
			if feature == "DNS" {
				below, at = "10.15.7", "11.0"
			}
			adeExec(t, s, `UPDATE mdm_apple_devices SET os_version=$2 WHERE id=$1`, mac.ID, below)
			identifier := "com.example.vpn-target." + channel + "." + feature
			p, err := s.SaveProfile(t.Context(), 1, "", 0, vpnConfigurationProfileData(t, channel, identifier, vpnSettings("VPN")), "admin")
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
			changedPayload := vpnSettings(feature)
			if feature == "DNS" {
				changedPayload = vpnSettings("VPN")
				changedPayload["DNS"] = map[string]any{"DNSProtocol": "Cleartext", "SupplementalMatchDomainsNoSearch": 0}
			}
			changed := vpnConfigurationProfileData(t, channel, identifier, changedPayload)
			var before, after int
			if err = s.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1)+(SELECT count(*) FROM mdm_apple_user_commands WHERE profile_id=$1)`, p.ID).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, changed, "admin"); err == nil {
				t.Fatal("VPN revision reached old target", feature, channel)
			}
			if err = s.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1)+(SELECT count(*) FROM mdm_apple_user_commands WHERE profile_id=$1)`, p.ID).Scan(&after); err != nil || after != before || len(revisionHistory(t, s, p.ID)) != 1 {
				t.Fatal("failed VPN revision leaked commands or history", err)
			}
			stored, err := s.Profile(t.Context(), 1, p.ID)
			if err != nil || stored.UUID != p.UUID || stored.Revision != 1 {
				t.Fatal("failed VPN revision changed catalog", err)
			}
			adeExec(t, s, `UPDATE mdm_apple_devices SET os_version=$2 WHERE id=$1`, mac.ID, at)
			if _, err = s.SaveProfile(t.Context(), 1, p.ID, 1, changed, "admin"); err != nil {
				t.Fatal("VPN revision rejected at supported boundary", channel, feature, err)
			}
			adeExec(t, s, `UPDATE mdm_apple_devices SET os_version=$2 WHERE id=$1`, mac.ID, below)
			if err = assign("installed"); err == nil {
				t.Fatal("VPN reassignment bypassed target check")
			}
			if err = assign("removed"); err != nil {
				t.Fatal("VPN prerequisite prevented removal", err)
			}
		}
	}
}

func TestVPNDNSCertificateTargetsRejectOldMacsAndPhones(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "VPN DNS Mac", "Mac16,1", "15.0")
	drainMacInventory(t, s, mac)
	u := testUserEnroll(t, s, mac, "alice")
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "VPN DNS phone", "iPhone16,1", "18.0")
	for _, channel := range []string{"System", "User"} {
		p, err := s.SaveProfile(t.Context(), 1, "", 0, vpnCertificateProfileData(t, channel, "DNS", "com.apple.vpn.managed", false), "admin")
		if err != nil {
			t.Fatal(err)
		}
		assign := func(id, desired string) error {
			if channel == "User" {
				return s.AssignUserProfile(t.Context(), scope, id, u.ID, p.ID, desired, "admin")
			}
			return s.AssignProfile(t.Context(), scope, p.ID, []string{id}, desired, "admin")
		}
		for _, target := range []struct{ id, below, at string }{{mac.ID, "12.7.6", "13.0"}, {phone.ID, "15.8.4", "16.0"}} {
			if channel == "User" && target.id == phone.ID {
				continue
			}
			adeExec(t, s, `UPDATE mdm_apple_devices SET os_version=$2 WHERE id=$1`, target.id, target.below)
			if err = assign(target.id, "installed"); err == nil {
				t.Fatal("DNS identity reached unsupported OS", channel)
			}
			adeExec(t, s, `UPDATE mdm_apple_devices SET os_version=$2 WHERE id=$1`, target.id, target.at)
			if err = assign(target.id, "installed"); err != nil {
				t.Fatal("DNS identity rejected at boundary", channel, err)
			}
			adeExec(t, s, `UPDATE mdm_apple_devices SET os_version=$2 WHERE id=$1`, target.id, target.below)
			if err = assign(target.id, "removed"); err != nil {
				t.Fatal("DNS identity prerequisite prevented removal", err)
			}
		}
	}
}

func TestAlwaysOnRequiresFreshSupervisedMobileInventoryAndPreservesRemoval(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	phone, _, _ := testEnrollPlatformWithKey(t, s, scope, "Always On phone", "iPhone16,1", "18.0")
	mac, _, _ := testEnrollPlatformWithKey(t, s, scope, "Always On unsupported Mac", "Mac16,1", "15.0")
	p, err := s.SaveProfile(t.Context(), 1, "", 0, vpnConfigurationProfileData(t, "System", "com.example.always-on", vpnSettings("AlwaysOn")), "admin")
	if err != nil {
		t.Fatal(err)
	}
	assign := func(id, desired string) error {
		return s.AssignProfile(t.Context(), scope, p.ID, []string{id}, desired, "admin")
	}
	if err = assign(mac.ID, "installed"); !errors.Is(err, ErrProfilePrerequisite) {
		t.Fatal("Always On reached Mac", err)
	}
	for _, state := range []string{"missing", "unreported", "stale", "future"} {
		adeExec(t, s, `UPDATE mdm_apple_devices SET supervised=true,supervised_reported=true,inventory_at=clock_timestamp() WHERE id=$1`, phone.ID)
		switch state {
		case "missing":
			adeExec(t, s, `UPDATE mdm_apple_devices SET supervised=false WHERE id=$1`, phone.ID)
		case "unreported":
			adeExec(t, s, `UPDATE mdm_apple_devices SET supervised_reported=false WHERE id=$1`, phone.ID)
		case "stale":
			adeExec(t, s, `UPDATE mdm_apple_devices SET inventory_at=clock_timestamp()-interval '25 hours' WHERE id=$1`, phone.ID)
		case "future":
			adeExec(t, s, `UPDATE mdm_apple_devices SET inventory_at=clock_timestamp()+interval '1 hour' WHERE id=$1`, phone.ID)
		}
		if err = assign(phone.ID, "installed"); !errors.Is(err, ErrProfilePrerequisite) {
			t.Fatal("Always On accepted insufficient supervision evidence", state, err)
		}
	}
	adeExec(t, s, `UPDATE mdm_apple_devices SET supervised=true,supervised_reported=true,inventory_at=clock_timestamp() WHERE id=$1`, phone.ID)
	if err = assign(phone.ID, "installed"); err != nil {
		t.Fatal(err)
	}
	adeExec(t, s, `UPDATE mdm_apple_devices SET supervised=false,inventory_at=clock_timestamp()-interval '25 hours' WHERE id=$1`, phone.ID)
	if err = assign(phone.ID, "removed"); err != nil {
		t.Fatal("Always On prerequisite prevented removal", err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1 AND device_id=$2 AND request_type='InstallProfile'`, p.ID, mac.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("unsupported Mac received an Always On command", err)
	}
}
