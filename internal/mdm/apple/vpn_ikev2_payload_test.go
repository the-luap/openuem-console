package apple

import (
	"strings"
	"testing"

	"howett.net/plist"
)

func TestIKEv2AuthenticationAndIntegerWireTypes(t *testing.T) {
	for _, auth := range []string{"None", "SharedSecret", "Certificate"} {
		for _, extended := range []int{0, 1} {
			p := vpnSettings("IKEv2")
			c := p["IKEv2"].(map[string]any)
			c["AuthenticationMethod"], c["ExtendedAuthEnabled"] = auth, extended
			c["TLSMinimumVersion"], c["TLSMaximumVersion"] = "1.2", "1.2"
			c["CertificateType"], c["ServerCertificateIssuerCommonName"] = "ECDSA256", "Synthetic VPN issuer"
			c["MTU"], c["IncludeAllNetworks"], c["ExcludeAPNs"] = 1280, 0, 1
			c["SharedSecret"] = " synthetic-private-value § "
			data, err := plist.Marshal(p, plist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if _, err = plist.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if err = validateVPNPayload(decoded, "User", &Device{Model: "Mac16,1", OSVersion: "15.0"}); err != nil {
				t.Fatal(err)
			}
			wire := decoded["IKEv2"].(map[string]any)
			if wire["ExtendedAuthEnabled"] != uint64(extended) || wire["IncludeAllNetworks"] != uint64(0) || wire["SharedSecret"] != " synthetic-private-value § " {
				t.Fatal("IKEv2 integers or secret text changed")
			}
			if _, exists := wire["PayloadCertificateUUID"]; exists {
				t.Fatal("uploaded IKEv2 acquired an implicit certificate reference")
			}
		}
	}
	for _, host := range []string{"vpn", "vpn.example.test.", "xn--bcher-kva.example", "192.0.2.42", "2001:db8::42"} {
		if !vpnServerAddress(host) {
			t.Fatal("valid IKEv2 server rejected", host)
		}
	}
	for _, host := range []string{"", "https://vpn.example.test", "vpn.example.test:500", "[2001:db8::42]", "fe80::1%en0", "*.example.test", "vpn..example", "-vpn.example", "vpn .example"} {
		if vpnServerAddress(host) {
			t.Fatal("invalid IKEv2 server accepted", host)
		}
	}
}

func TestIKEv2RejectsInvalidAuthenticationTLSAndSecurityAssociations(t *testing.T) {
	for _, bad := range []struct {
		key   string
		value any
	}{
		{"RemoteAddress", "https://synthetic-private-value"}, {"LocalIdentifier", ""}, {"RemoteIdentifier", true}, {"AuthenticationMethod", "Password"},
		{"CertificateType", "RSA"}, {"CertificateType", "synthetic-private-value"}, {"SharedSecret", []byte("synthetic-private-value")},
		{"TLSMinimumVersion", "1.3"}, {"TLSMaximumVersion", 1.2}, {"ExtendedAuthEnabled", true},
		{"NATKeepAliveInterval", 19}, {"DisconnectOnIdleTimer", -1}, {"MTU", 1279}, {"MTU", 1401},
		{"DeadPeerDetectionRate", "Immediate"}, {"ProviderType", "synthetic-private-value"},
		{"PPK", []byte{1, 2}}, {"PPKIdentifier", "synthetic-private-value"},
		{"IKESecurityAssociationParameters", true},
		{"ChildSecurityAssociationParameters", map[string]any{"EncryptionAlgorithm": "synthetic-private-value"}},
		{"IKESecurityAssociationParameters", map[string]any{"IntegrityAlgorithm": "MD5"}},
		{"IKESecurityAssociationParameters", map[string]any{"DiffieHellmanGroup": 13}},
		{"IKESecurityAssociationParameters", map[string]any{"DiffieHellmanGroup": "14"}},
		{"IKESecurityAssociationParameters", map[string]any{"LifeTimeInMinutes": 9}},
		{"IKESecurityAssociationParameters", map[string]any{"LifeTimeInMinutes": 1441}},
		{"IKESecurityAssociationParameters", map[string]any{"PostQuantumKeyExchangeMethods": []any{38}}},
		{"IKESecurityAssociationParameters", map[string]any{"PostQuantumKeyExchangeMethods": []any{true}}},
		{"IKESecurityAssociationParameters", map[string]any{"PostQuantumKeyExchangeMethods": []any{}}},
		{"IKESecurityAssociationParameters", map[string]any{"PostQuantumKeyExchangeMethods": []any{0, 0, 0, 0, 0, 0, 0, 0}}},
	} {
		p := vpnSettings("IKEv2")
		p["IKEv2"].(map[string]any)[bad.key] = bad.value
		if err := validateVPNPayload(p, "System", nil); err == nil || strings.Contains(err.Error(), "synthetic-private-value") {
			t.Fatal("malformed IKEv2 accepted or secret echoed", bad.key, err)
		}
	}
	p := vpnSettings("IKEv2")
	c := p["IKEv2"].(map[string]any)
	c["TLSMinimumVersion"], c["TLSMaximumVersion"] = "1.2", "1.1"
	if err := validateVPNPayload(p, "System", nil); err == nil {
		t.Fatal("inverted IKEv2 TLS range accepted")
	}
	for key := range ikev2FlagVersions {
		for _, bad := range []any{true, "0", -1, 2, 0.0} {
			p := vpnSettings("IKEv2")
			p["IKEv2"].(map[string]any)[key] = bad
			if err := validateVPNPayload(p, "System", nil); err == nil {
				t.Fatal("invalid IKEv2 integer flag accepted", key)
			}
		}
	}
}

func TestIKEv2PresenceBasedVersionsAndPlatformRestrictions(t *testing.T) {
	for _, tc := range []struct {
		settings                             map[string]any
		macBelow, macAt, phoneBelow, phoneAt string
	}{
		{map[string]any{}, "10.10", "10.11", "7.1", "8.0"},
		{map[string]any{"TLSMaximumVersion": "1.2"}, "10.12", "10.13", "10.3", "11.0"},
		{map[string]any{"MTU": 1280}, "10.15", "11.0", "13.7", "14.0"},
		{map[string]any{"ExcludeAPNs": 0}, "13.2", "13.3", "16.3", "16.4"},
		{map[string]any{"ExcludeDeviceCommunication": 0}, "14.3", "14.4", "17.3", "17.4"},
		{map[string]any{"PPK": []byte{1, 2, 3}, "PPKIdentifier": "synthetic-key"}, "14.7", "15.0", "17.7", "18.0"},
		{map[string]any{"EnforceStrictAlgorithmSelection": 0}, "15.4", "15.5", "18.4", "18.5"},
		{map[string]any{"AllowPostQuantumKeyExchangeFallback": 0}, "15.6", "26.0", "18.6", "26.0"},
		{map[string]any{"IKESecurityAssociationParameters": map[string]any{"PostQuantumKeyExchangeMethods": []any{0, 36, 37}}}, "15.6", "26.0", "18.6", "26.0"},
	} {
		p := vpnSettings("IKEv2")
		for key, value := range tc.settings {
			p["IKEv2"].(map[string]any)[key] = value
		}
		for _, target := range []struct{ model, below, at string }{{"Mac16,1", tc.macBelow, tc.macAt}, {"iPhone16,1", tc.phoneBelow, tc.phoneAt}} {
			d := &Device{Model: target.model, OSVersion: target.below}
			if err := validateVPNPayload(p, "System", d); err == nil {
				t.Fatal("IKEv2 property reached unsupported version", target, tc.settings)
			}
			d.OSVersion = target.at
			if err := validateVPNPayload(p, "System", d); err != nil {
				t.Fatal("IKEv2 boundary rejected", target, err)
			}
		}
	}
	for _, key := range []string{"EnableFallback", "OnDemandUserOverrideDisabled"} {
		p := vpnSettings("IKEv2")
		p["IKEv2"].(map[string]any)[key] = 0
		if err := validateVPNPayload(p, "User", &Device{Model: "Mac16,1", OSVersion: "26.0"}); err == nil {
			t.Fatal("mobile IKEv2 property reached Mac even when zero", key)
		}
		if err := validateVPNPayload(p, "User", nil); err == nil {
			t.Fatal("mobile IKEv2 property accepted on User profile upload", key)
		}
	}
}

func TestIKEv2StrictSelectionAndRemovedAlgorithms(t *testing.T) {
	for _, settings := range []map[string]any{{"EncryptionAlgorithm": "DES"}, {"EncryptionAlgorithm": "3DES"}, {"IntegrityAlgorithm": "SHA1-96"}, {"IntegrityAlgorithm": "SHA1-160"}, {"DiffieHellmanGroup": 5}} {
		p := vpnSettings("IKEv2")
		c := p["IKEv2"].(map[string]any)
		c["IKESecurityAssociationParameters"] = settings
		for _, model := range []string{"Mac16,1", "iPhone16,1"} {
			d := &Device{Model: model, OSVersion: "18.6"}
			if model == "Mac16,1" {
				d.OSVersion = "15.6"
			}
			if err := validateVPNPayload(p, "System", d); err != nil {
				t.Fatal("legacy upload was globally disabled", err)
			}
			d.OSVersion = "26.0"
			if err := validateVPNPayload(p, "System", d); err == nil {
				t.Fatal("removed IKEv2 algorithm reached OS 26")
			}
		}
		if _, integrityOnly := settings["IntegrityAlgorithm"]; !integrityOnly {
			c["EnforceStrictAlgorithmSelection"] = 1
			if err := validateVPNPayload(p, "System", nil); err == nil {
				t.Fatal("strict selection accepted a weak algorithm")
			}
		}
	}
	p := vpnSettings("IKEv2")
	c := p["IKEv2"].(map[string]any)
	c["EnforceStrictAlgorithmSelection"] = 1
	c["IKESecurityAssociationParameters"] = map[string]any{"EncryptionAlgorithm": "AES-128"}
	// Omitted child settings inherit IKE settings, whereas an explicit empty
	// child dictionary uses Apple's defaults, including AES-256.
	if err := validateVPNPayload(p, "System", nil); err != nil {
		t.Fatal("inherited child algorithm changed", err)
	}
	c["ChildSecurityAssociationParameters"] = map[string]any{}
	if err := validateVPNPayload(p, "System", nil); err == nil {
		t.Fatal("strict selection accepted a weaker IKE algorithm than child")
	}
	c["IKESecurityAssociationParameters"] = map[string]any{"EncryptionAlgorithm": "AES-256-GCM", "DiffieHellmanGroup": 19, "LifeTimeInMinutes": 1440}
	if err := validateVPNPayload(p, "System", &Device{Model: "Mac16,1", OSVersion: "26.0"}); err != nil {
		t.Fatal(err)
	}
}
