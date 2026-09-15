package apple

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"howett.net/plist"
)

func ikev2CompositionOptions(p *Profile) IKEv2CertificateOptions {
	return IKEv2CertificateOptions{Name: "Certificate VPN", Identifier: "com.example.ikev2-composed." + uuid.NewString(), Scope: p.Scope, ConnectionName: "Corporate VPN", RemoteAddress: "vpn.example.test", LocalIdentifier: "device.example.test", RemoteIdentifier: "vpn.example.test", AuthenticationMode: "eap-tls", CertificateType: "RSA", ServerCertificateIssuerCommonName: "Synthetic issuer", ServerCertificateCommonName: "vpn-certificate.example.test", Identity: CertificateProfileReference{ProfileID: p.ID, Revision: p.Revision}}
}

func TestIKEv2CompositionUsesExactRevisionsAndAtomicEncryptedProvenance(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	for _, channel := range []string{"System", "User"} {
		identity := saveWiFiCertificateSource(t, s, channel, "scep")
		trust := saveWiFiCertificateSource(t, s, channel, "trust")
		o := ikev2CompositionOptions(identity)
		o.Trust = &CertificateProfileReference{ProfileID: trust.ID, Revision: trust.Revision}
		first := revisionHistory(t, s, identity.ID)[0]
		changed := bytes.ReplaceAll(identity.Payload, []byte("synthetic-wifi-certificate-secret"), []byte("synthetic-new-issuer-secret"))
		if _, err := s.SaveProfile(t.Context(), 1, identity.ID, 1, changed, "admin"); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteProfile(t.Context(), 1, identity.ID, "admin"); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteProfile(t.Context(), 1, trust.ID, "admin"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateIKEv2CertificateProfile(t.Context(), 1, o, "admin", nil); !errors.Is(err, access.ErrDenied) {
			t.Fatal("VPN composition bypassed transaction authorization", err)
		}
		p, err := s.createIKEv2CertificateProfile(t.Context(), 1, o, "admin", nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.Scope != channel || p.Revision != 1 || !bytes.Contains(p.Payload, []byte("synthetic-wifi-certificate-secret")) || bytes.Contains(p.Payload, []byte("synthetic-new-issuer-secret")) || !bytes.Contains(p.Payload, []byte("Source changes do not update this copy.")) {
			t.Fatal("VPN composition replaced a pinned revision or lost provenance")
		}
		var root map[string]any
		if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
			t.Fatal(err)
		}
		if err = validateProfileCertificateReferences(root); err != nil || len(root["PayloadContent"].([]any)) != 3 {
			t.Fatal("VPN composition lost local references or trust", err)
		}
		vpn := root["PayloadContent"].([]any)[0].(map[string]any)
		c := vpn["IKEv2"].(map[string]any)
		if vpn["UserDefinedName"] != o.ConnectionName || c["ExtendedAuthEnabled"] != uint64(1) || c["ServerCertificateCommonName"] != o.ServerCertificateCommonName || c["TLSMinimumVersion"] != "1.2" {
			t.Fatal("VPN composition option mapping changed")
		}
		var audit []byte
		if err = s.db.QueryRow(`SELECT details FROM mdm_apple_audit WHERE action='apple.profile.compose' AND resource_id=$1`, p.ID).Scan(&audit); err != nil {
			t.Fatal(err)
		}
		var provenance struct {
			Sources []struct {
				RevisionID string `json:"revision_id"`
				ProfileID  string `json:"profile_id"`
				Revision   int    `json:"revision"`
			} `json:"source_revisions"`
		}
		if err = json.Unmarshal(audit, &provenance); err != nil || len(provenance.Sources) != 2 || provenance.Sources[0].RevisionID != first.ID || provenance.Sources[0].ProfileID != identity.ID || provenance.Sources[0].Revision != 1 || provenance.Sources[1].ProfileID != trust.ID {
			t.Fatal("VPN composition audit lost exact revisions", err)
		}
		if bytes.Contains(audit, []byte("synthetic-wifi-certificate-secret")) {
			t.Fatal("VPN composition audit exposed credentials")
		}
		for _, query := range []string{`SELECT payload FROM mdm_apple_profiles WHERE id=$1`, `SELECT encrypted_payload FROM mdm_apple_profile_revisions WHERE profile_id=$1`} {
			var encrypted []byte
			if err = s.db.QueryRow(query, p.ID).Scan(&encrypted); err != nil || bytes.Contains(encrypted, []byte("synthetic-wifi-certificate-secret")) {
				t.Fatal("VPN composition persistence exposed credentials", err)
			}
		}
		var commands int
		if err = s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE profile_id=$1`, p.ID).Scan(&commands); err != nil || commands != 0 {
			t.Fatal("VPN creation implicitly assigned a device", err)
		}
	}
}

func TestIKEv2CompositionRejectsForeignInvalidAndUnauditedCopies(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	identity := saveWiFiCertificateSource(t, s, "System", "scep")
	trust := saveWiFiCertificateSource(t, s, "System", "trust")
	o := ikev2CompositionOptions(identity)
	o.Trust = &CertificateProfileReference{ProfileID: trust.ID, Revision: trust.Revision}
	var before, after int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_profiles`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*IKEv2CertificateOptions){
		func(o *IKEv2CertificateOptions) { o.Identity.Revision = 999 }, func(o *IKEv2CertificateOptions) { o.Identity.ProfileID = uuid.NewString() },
		func(o *IKEv2CertificateOptions) { o.Identity = *o.Trust }, func(o *IKEv2CertificateOptions) { o.Scope = "User" },
		func(o *IKEv2CertificateOptions) { o.CertificateType = "ECDSA256" }, func(o *IKEv2CertificateOptions) { o.RemoteAddress = "https://vpn.example.test" },
	} {
		bad := o
		bad.Identifier = "com.example.ikev2-invalid." + uuid.NewString()
		change(&bad)
		if _, err := s.createIKEv2CertificateProfile(t.Context(), 1, bad, "admin", nil); err == nil {
			t.Fatal("invalid VPN composition saved")
		}
	}
	if _, err := s.createIKEv2CertificateProfile(t.Context(), 2, o, "admin", nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("VPN source crossed organization", err)
	}
	adeExec(t, s, `CREATE FUNCTION reject_vpn_compose_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.profile.compose' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_vpn_compose_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION reject_vpn_compose_audit()`)
	if _, err := s.createIKEv2CertificateProfile(t.Context(), 1, o, "admin", nil); err == nil {
		t.Fatal("VPN composition succeeded without its audit")
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_profiles`).Scan(&after); err != nil || after != before {
		t.Fatal("failed VPN composition leaked catalog state", err)
	}
	var history int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_profile_revisions WHERE identifier=$1`, o.Identifier).Scan(&history); err != nil || history != 0 {
		t.Fatal("failed VPN audit leaked a retained revision", err)
	}
}
