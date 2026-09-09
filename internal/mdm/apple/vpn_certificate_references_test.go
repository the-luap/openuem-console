package apple

import (
	"strings"
	"testing"

	"howett.net/plist"
)

func vpnReferenceFixture(protocol string) (map[string]any, map[string]any, map[string]any, map[string]any) {
	root, network, identity, anchor := referenceFixture()
	delete(network, "EAPClientConfiguration")
	delete(network, "PayloadCertificateUUID")
	network["PayloadType"] = "com.apple.vpn.managed"
	network["VPNType"] = protocol
	network["UserDefinedName"] = "Synthetic VPN"
	configuration := map[string]any{"RemoteAddress": "vpn.example.test", "AuthenticationMethod": "Certificate", "PayloadCertificateUUID": identity["PayloadUUID"]}
	network[protocol] = configuration
	return root, configuration, identity, anchor
}

func TestVPNCertificateReferencesResolveOnlyLocalIdentityPayloads(t *testing.T) {
	for _, protocol := range []string{"VPN", "IPSec", "IKEv2", "TransparentProxy"} {
		for _, kind := range []string{"com.apple.security.scep", "com.apple.security.acme", "com.apple.security.pkcs12", "com.apple.ADCertificate.managed"} {
			root, configuration, identity, _ := vpnReferenceFixture(protocol)
			identity["PayloadType"] = kind
			configuration["PayloadCertificateUUID"] = strings.ToUpper(identity["PayloadUUID"].(string))
			data, err := plist.Marshal(root, plist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if _, err = plist.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if err = validateProfileCertificateReferences(decoded); err != nil {
				t.Fatal(protocol, kind, err)
			}
		}
		root, configuration, _, _ := vpnReferenceFixture(protocol)
		delete(configuration, "PayloadCertificateUUID")
		configuration["AuthenticationMethod"] = "SharedSecret"
		if err := validateProfileCertificateReferences(root); err != nil {
			t.Fatal("VPN without identity reference acquired a certificate requirement", err)
		}
	}
}

func TestVPNCertificateReferencesRejectExternalPublicAmbiguousAndMalformedValues(t *testing.T) {
	for _, protocol := range []string{"VPN", "IPSec", "IKEv2", "TransparentProxy"} {
		for _, change := range []func(map[string]any, map[string]any, map[string]any, map[string]any){
			func(r, c, i, a map[string]any) { c["PayloadCertificateUUID"] = r["PayloadUUID"] },
			func(r, c, i, a map[string]any) { c["PayloadCertificateUUID"] = "eeeeeeee-0000-4000-8000-000000000005" },
			func(r, c, i, a map[string]any) { c["PayloadCertificateUUID"] = a["PayloadUUID"] },
			func(r, c, i, a map[string]any) { c["PayloadCertificateUUID"] = "synthetic-vpn-private-value" },
			func(r, c, i, a map[string]any) { c["PayloadCertificateUUID"] = true },
			func(r, c, i, a map[string]any) { a["PayloadUUID"] = strings.ToUpper(i["PayloadUUID"].(string)) },
			func(r, c, i, a map[string]any) { i["PayloadType"] = "com.apple.mdm" },
			func(r, c, i, a map[string]any) {
				r["PayloadContent"].([]any)[0].(map[string]any)[protocol] = "synthetic-vpn-private-value"
			},
		} {
			root, configuration, identity, anchor := vpnReferenceFixture(protocol)
			change(root, configuration, identity, anchor)
			if err := validateProfileCertificateReferences(root); err == nil || strings.Contains(err.Error(), "synthetic-vpn-private-value") {
				t.Fatal("invalid VPN certificate binding accepted or value echoed", protocol, err)
			}
		}
	}
}

func TestAppLayerVPNReferencesUseTheSameLocalIdentityRules(t *testing.T) {
	for _, protocol := range []string{"VPN", "IPSec", "IKEv2"} {
		root, configuration, _, anchor := vpnReferenceFixture(protocol)
		network := root["PayloadContent"].([]any)[0].(map[string]any)
		network["PayloadType"] = "com.apple.vpn.managed.applayer"
		network["VPNUUID"] = "ffffffff-0000-4000-8000-000000000006"
		if err := validateProfileCertificateReferences(root); err != nil {
			t.Fatal(protocol, err)
		}
		for _, bad := range []any{network["VPNUUID"], root["PayloadUUID"], anchor["PayloadUUID"], false} {
			configuration["PayloadCertificateUUID"] = bad
			if err := validateProfileCertificateReferences(root); err == nil {
				t.Fatal("app-layer VPN accepted a connection UUID, root UUID or public identity", protocol)
			}
		}
	}
}
