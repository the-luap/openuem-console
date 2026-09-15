package apple

import (
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func vpnSettings(protocol string) map[string]any {
	p := map[string]any{"PayloadType": "com.apple.vpn.managed", "VPNType": protocol, "UserDefinedName": "Synthetic VPN", protocol: map[string]any{}}
	if protocol == "VPN" || protocol == "TransparentProxy" {
		p["VPNSubType"] = "com.example.synthetic-provider"
	}
	if protocol == "L2TP" {
		delete(p, protocol)
		p["PPP"] = map[string]any{}
	}
	if protocol == "IKEv2" {
		p[protocol] = map[string]any{"RemoteAddress": "vpn.example.test", "LocalIdentifier": "device.example.test", "RemoteIdentifier": "vpn.example.test", "AuthenticationMethod": "Certificate"}
	}
	if protocol == "AlwaysOn" {
		p[protocol] = map[string]any{"TunnelConfigurations": []any{map[string]any{"ProtocolType": "IKEv2", "Interfaces": []any{"WiFi", "Cellular"}, "RemoteAddress": "vpn.example.test", "LocalIdentifier": "device.example.test", "RemoteIdentifier": "vpn.example.test", "AuthenticationMethod": "Certificate"}}}
	}
	return p
}

func TestVPNOuterConfigurationAndDNSWireTypes(t *testing.T) {
	for _, protocol := range []string{"VPN", "IPSec", "IKEv2", "L2TP", "TransparentProxy", "AlwaysOn"} {
		p := vpnSettings(protocol)
		if err := validateVPNPayload(p, "System", nil); err != nil {
			t.Fatal(protocol, err)
		}
	}
	for _, protocol := range []string{"Cleartext", "HTTPS", "TLS"} {
		p := vpnSettings("VPN")
		dns := map[string]any{"DNSProtocol": protocol, "ServerAddresses": []any{"192.0.2.53", "2001:db8::53"}, "SearchDomains": []any{"example.test"}, "SupplementalMatchDomains": []any{"", "internal.example.test"}, "SupplementalMatchDomainsNoSearch": 0}
		if protocol == "HTTPS" {
			dns["ServerURL"] = "https://resolver.example.test/dns-query{?dns}"
		}
		if protocol == "TLS" {
			dns["ServerName"] = "resolver.example.test"
		}
		p["DNS"] = dns
		data, err := plist.Marshal(p, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if _, err = plist.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if err = validateVPNPayload(decoded, "User", &Device{Model: "Mac16,1", OSVersion: "15.0"}); err != nil {
			t.Fatal(protocol, err)
		}
		actual := decoded["DNS"].(map[string]any)
		if value, ok := certificateInteger(actual["SupplementalMatchDomainsNoSearch"]); !ok || value != 0 || actual["SupplementalMatchDomains"].([]any)[0] != "" {
			t.Fatal("DNS integer zero or default domain changed during serialization")
		}
	}
}

func TestVPNRejectsMalformedConfigurationWithoutEchoingValues(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"missing name":                    func(p map[string]any) { delete(p, "UserDefinedName") },
		"invalid name":                    func(p map[string]any) { p["UserDefinedName"] = "synthetic-private-value\n" },
		"unknown type":                    func(p map[string]any) { p["VPNType"] = "synthetic-private-value" },
		"missing configuration":           func(p map[string]any) { delete(p, "VPN") },
		"invalid unrelated configuration": func(p map[string]any) { p["IPSec"] = "synthetic-private-value" },
		"missing provider":                func(p map[string]any) { delete(p, "VPNSubType") },
		"invalid provider":                func(p map[string]any) { p["VPNSubType"] = []any{"synthetic-private-value"} },
		"invalid DNS":                     func(p map[string]any) { p["DNS"] = "synthetic-private-value" },
		"app-layer missing UUID":          func(p map[string]any) { p["PayloadType"] = "com.apple.vpn.managed.applayer" },
	} {
		t.Run(name, func(t *testing.T) {
			p := vpnSettings("VPN")
			change(p)
			if err := validateVPNPayload(p, "System", nil); err == nil || strings.Contains(err.Error(), "synthetic-private-value") {
				t.Fatal("malformed VPN accepted or value echoed", err)
			}
		})
	}
	for _, dns := range []map[string]any{
		{"DNSProtocol": "synthetic-private-value"}, {"DNSProtocol": true},
		{"DNSProtocol": "HTTPS"}, {"ServerURL": "http://resolver.example.test"},
		{"ServerURL": "https://user:synthetic-private-value@resolver.example.test"},
		{"ServerURL": "https://resolver.example.test/#synthetic-private-value"},
		{"DNSProtocol": "TLS"}, {"ServerName": "https://resolver.example.test"},
		{"ServerName": "resolver"}, {"ServerName": "*.example.test"},
		{"ServerAddresses": []any{}}, {"ServerAddresses": []any{"resolver.example.test"}},
		{"ServerAddresses": []any{"fe80::1%en0"}}, {"ServerAddresses": []any{"192.0.2.53:53"}},
		{"SearchDomains": []any{true}}, {"SearchDomains": []any{""}},
		{"SupplementalMatchDomains": []any{" example.test"}},
		{"SupplementalMatchDomainsNoSearch": false}, {"SupplementalMatchDomainsNoSearch": "0"},
		{"SupplementalMatchDomainsNoSearch": 2}, {"SupplementalMatchDomainsNoSearch": -1},
		{"DomainName": "synthetic-private-value\n"}, {"PayloadCertificateUUID": true},
	} {
		p := vpnSettings("VPN")
		p["DNS"] = dns
		if err := validateVPNPayload(p, "System", nil); err == nil || strings.Contains(err.Error(), "synthetic-private-value") {
			t.Fatal("malformed DNS accepted or value echoed", err)
		}
	}
	for _, protocol := range []string{"L2TP", "TransparentProxy", "AlwaysOn"} {
		p := vpnSettings(protocol)
		p["PayloadType"], p["VPNUUID"] = "com.apple.vpn.managed.applayer", "eeeeeeee-0000-4000-8000-000000000005"
		if err := validateVPNPayload(p, "System", nil); err == nil {
			t.Fatal("unsupported app-layer VPN type accepted", protocol)
		}
	}
}

func TestVPNDNSPropertyPresenceRequiresCompatibleTargets(t *testing.T) {
	for _, tc := range []struct {
		dns                                  map[string]any
		macBelow, macAt, phoneBelow, phoneAt string
	}{
		{map[string]any{"ServerAddresses": []any{"192.0.2.53"}}, "10.11.6", "10.12", "9.3.6", "10.0"},
		{map[string]any{"SupplementalMatchDomainsNoSearch": 0}, "10.11.6", "10.12", "9.3.6", "10.0"},
		{map[string]any{"DNSProtocol": "Cleartext"}, "10.15.7", "11.0", "13.7", "14.0"},
		{map[string]any{"ServerURL": "https://resolver.example.test/dns-query"}, "10.15.7", "11.0", "13.7", "14.0"},
		{map[string]any{"ServerName": "resolver.example.test"}, "10.15.7", "11.0", "13.7", "14.0"},
		{map[string]any{"PayloadCertificateUUID": "eeeeeeee-0000-4000-8000-000000000005"}, "12.7.6", "13.0", "15.8.4", "16.0"},
	} {
		p := vpnSettings("VPN")
		p["DNS"] = tc.dns
		for _, target := range []struct{ model, below, at string }{{"Mac16,1", tc.macBelow, tc.macAt}, {"iPhone16,1", tc.phoneBelow, tc.phoneAt}, {"iPad14,1", tc.phoneBelow, tc.phoneAt}} {
			for _, channel := range []string{"System", "User"} {
				d := &Device{Model: target.model, OSVersion: target.below}
				if err := validateVPNPayload(p, channel, d); err == nil {
					t.Fatal("VPN DNS reached old target", target, channel)
				}
				d.OSVersion = target.at
				err := validateVPNPayload(p, channel, d)
				want := channel == "System" || target.model == "Mac16,1"
				if (err == nil) != want {
					t.Fatal("VPN DNS boundary/channel mismatch", target, channel, err)
				}
			}
		}
	}
}

func TestVPNTransparentProxyAndAppLayerTargets(t *testing.T) {
	p := vpnSettings("TransparentProxy")
	for _, channel := range []string{"System", "User"} {
		for _, tc := range []struct {
			model, version string
			want           bool
		}{{"Mac16,1", "13.6", false}, {"Mac16,1", "14.0", true}, {"iPhone16,1", "18.0", false}, {"iPad14,1", "18.0", false}, {"Other", "14.0", false}, {"Mac16,1", "", false}} {
			if err := validateVPNPayload(p, channel, &Device{Model: tc.model, OSVersion: tc.version}); (err == nil) != tc.want {
				t.Fatal(tc, channel, err)
			}
		}
	}
	p = vpnSettings("VPN")
	p["PayloadType"], p["VPNUUID"] = "com.apple.vpn.managed.applayer", "eeeeeeee-0000-4000-8000-000000000005"
	for _, tc := range []struct {
		model, version string
		want           bool
	}{{"Mac16,1", "10.8", false}, {"Mac16,1", "10.9", true}, {"iPhone16,1", "6.1", false}, {"iPhone16,1", "7.0", true}} {
		if err := validateVPNPayload(p, "System", &Device{Model: tc.model, OSVersion: tc.version}); (err == nil) != tc.want {
			t.Fatal(tc, err)
		}
	}
	d := &Device{Model: "Mac16,1", OSVersion: "15.0", SecurityInventory: map[string]any{"ManagementStatus": map[string]any{"IsUserEnrollment": true}}}
	if err := validateVPNPayload(p, "System", d); err != nil {
		t.Fatal("app-layer scope confused with User Enrollment", err)
	}
	p["PayloadType"] = "com.apple.vpn.managed"
	if err := validateVPNPayload(p, "System", d); err == nil {
		t.Fatal("regular VPN reached User Enrollment")
	}
}

func TestAlwaysOnRequiresDeviceScopeFreshSupervisionAndMobilePlatform(t *testing.T) {
	p := vpnSettings("AlwaysOn")
	now := time.Now()
	for _, model := range []string{"iPhone16,1", "iPad14,1"} {
		d := &Device{Model: model, OSVersion: "8.0", Supervised: true, SupervisedReported: true, InventoryAt: &now}
		if err := validateVPNPayload(p, "System", d); err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*Device){
			func(d *Device) { d.Model = "Mac16,1"; d.OSVersion = "15.0" },
			func(d *Device) { d.OSVersion = "7.1" }, func(d *Device) { d.Supervised = false },
			func(d *Device) { d.SupervisedReported = false }, func(d *Device) { d.InventoryAt = nil },
			func(d *Device) { at := now.Add(-25 * time.Hour); d.InventoryAt = &at },
			func(d *Device) { at := now.Add(time.Hour); d.InventoryAt = &at },
		} {
			bad := *d
			change(&bad)
			if err := validateVPNPayload(p, "System", &bad); err == nil {
				t.Fatal("Always On prerequisite bypassed")
			}
		}
	}
	if err := validateVPNPayload(p, "User", nil); err == nil {
		t.Fatal("Always On accepted on Mac User channel")
	}
	for _, tunnels := range []any{nil, []any{}, []any{true}, []any{map[string]any{"ProtocolType": "VPN"}}, []any{map[string]any{"ProtocolType": "IKEv2", "Interfaces": []any{"WiFi", "WiFi"}}}, []any{map[string]any{"ProtocolType": "IKEv2", "Interfaces": []any{true}}}} {
		p["AlwaysOn"] = map[string]any{"TunnelConfigurations": tunnels}
		if err := validateVPNPayload(p, "System", nil); err == nil {
			t.Fatal("malformed Always On tunnel structure accepted")
		}
	}
}
