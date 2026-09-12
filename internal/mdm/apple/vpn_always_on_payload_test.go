package apple

import (
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func alwaysOnReferenceFixture() (map[string]any, map[string]any, map[string]any, map[string]any) {
	root, configuration, identity, anchor := vpnReferenceFixture("IKEv2")
	vpn := root["PayloadContent"].([]any)[0].(map[string]any)
	delete(vpn, "IKEv2")
	vpn["VPNType"] = "AlwaysOn"
	configuration["ProtocolType"] = "IKEv2"
	configuration["LocalIdentifier"], configuration["RemoteIdentifier"] = "device.example.test", "vpn.example.test"
	vpn["AlwaysOn"] = map[string]any{"TunnelConfigurations": []any{configuration}}
	return root, configuration, identity, anchor
}

func TestAlwaysOnResolvesEveryFlatTunnelIdentity(t *testing.T) {
	for _, kind := range []string{"com.apple.security.scep", "com.apple.security.acme", "com.apple.security.pkcs12", "com.apple.ADCertificate.managed"} {
		root, tunnel, identity, anchor := alwaysOnReferenceFixture()
		identity["PayloadType"] = kind
		tunnel["PayloadCertificateUUID"] = strings.ToUpper(identity["PayloadUUID"].(string))
		vpn := root["PayloadContent"].([]any)[0].(map[string]any)
		always := vpn["AlwaysOn"].(map[string]any)
		second := map[string]any{}
		for key, value := range tunnel {
			second[key] = value
		}
		tunnel["Interfaces"], second["Interfaces"] = []any{"WiFi"}, []any{"Cellular"}
		always["TunnelConfigurations"] = []any{tunnel, second}
		data, err := plist.Marshal(root, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if _, err = plist.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if err = validateProfileCertificateReferences(decoded); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []any{root["PayloadUUID"], anchor["PayloadUUID"], "eeeeeeee-0000-4000-8000-000000000005", true, "synthetic-private-value"} {
			second["PayloadCertificateUUID"] = bad
			if err = validateProfileCertificateReferences(root); err == nil || strings.Contains(err.Error(), "synthetic-private-value") {
				t.Fatal("valid first tunnel masked invalid second identity", err)
			}
		}
		delete(second, "PayloadCertificateUUID")
		if err = validateProfileCertificateReferences(root); err != nil {
			t.Fatal("tunnel without reference acquired an identity requirement", err)
		}
		anchor["PayloadUUID"] = strings.ToUpper(identity["PayloadUUID"].(string))
		if err = validateProfileCertificateReferences(root); err == nil {
			t.Fatal("Always On resolved ambiguous identity")
		}
	}
	for _, bad := range []any{true, map[string]any{}, map[string]any{"TunnelConfigurations": []any{true}}, map[string]any{"TunnelConfigurations": []any{}}} {
		root, _, _, _ := alwaysOnReferenceFixture()
		root["PayloadContent"].([]any)[0].(map[string]any)["AlwaysOn"] = bad
		if err := validateProfileCertificateReferences(root); err == nil {
			t.Fatal("invalid Always On structure bypassed references")
		}
	}
}

func TestAlwaysOnAppliesIKEv2TypesVersionsAndDiffieHellmanLimits(t *testing.T) {
	now := time.Now()
	d := &Device{Model: "iPhone16,1", OSVersion: "14.1", Supervised: true, SupervisedReported: true, InventoryAt: &now}
	p := vpnSettings("AlwaysOn")
	a := p["AlwaysOn"].(map[string]any)
	tunnel := a["TunnelConfigurations"].([]any)[0].(map[string]any)
	for _, key := range []string{"IKESecurityAssociationParameters", "ChildSecurityAssociationParameters"} {
		tunnel[key] = map[string]any{"DiffieHellmanGroup": 5}
		d.OSVersion = "14.1"
		if err := validateVPNPayload(p, "System", d); err != nil {
			t.Fatal(err)
		}
		d.OSVersion = "14.2"
		if err := validateVPNPayload(p, "System", d); err == nil {
			t.Fatal("Always On accepted a small DH group on iOS 14.2")
		}
		tunnel[key] = map[string]any{"DiffieHellmanGroup": 14}
		if err := validateVPNPayload(p, "System", d); err != nil {
			t.Fatal(err)
		}
		delete(tunnel, key)
	}
	tunnel["TLSMinimumVersion"], tunnel["TLSMaximumVersion"] = "1.2", "1.2"
	d.OSVersion = "10.3"
	if err := validateVPNPayload(p, "System", d); err == nil {
		t.Fatal("Always On ignored nested TLS version")
	}
	d.OSVersion = "11.0"
	if err := validateVPNPayload(p, "System", d); err != nil {
		t.Fatal(err)
	}
	tunnel["ExtendedAuthEnabled"] = true
	if err := validateVPNPayload(p, "System", nil); err == nil {
		t.Fatal("Always On ignored invalid nested IKEv2 type")
	}
	delete(tunnel, "ExtendedAuthEnabled")
	for _, key := range []string{"UIToggleEnabled", "AllowCaptiveWebSheet", "AllowAllCaptiveNetworkPlugins"} {
		a[key] = false
		if err := validateVPNPayload(p, "System", nil); err == nil {
			t.Fatal("Always On accepted boolean instead of integer", key)
		}
		a[key] = 0
		if err := validateVPNPayload(p, "System", nil); err != nil {
			t.Fatal(err)
		}
	}
	delete(tunnel, "RemoteAddress")
	tunnel["IKEv2"] = map[string]any{"RemoteAddress": "vpn.example.test", "LocalIdentifier": "device.example.test", "RemoteIdentifier": "vpn.example.test", "AuthenticationMethod": "Certificate"}
	if err := validateVPNPayload(p, "System", nil); err == nil {
		t.Fatal("nested IKEv2 dictionary replaced required flat tunnel settings")
	}
}
