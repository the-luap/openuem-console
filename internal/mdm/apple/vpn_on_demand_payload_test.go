package apple

import (
	"bytes"
	"strings"
	"testing"

	"howett.net/plist"
)

func vpnOnDemandRuleFixture() map[string]any {
	return map[string]any{
		"Action": "EvaluateConnection", "InterfaceTypeMatch": "WiFi",
		"DNSDomainMatch":        []any{"*.example.test", "example.test"},
		"DNSServerAddressMatch": []any{"17.*", "2001:db8::1"},
		"SSIDMatch":             []any{" Company café ", " "},
		"URLStringProbe":        "http://probe.example.test/reachable?network=office",
		"ActionParameters": []any{
			map[string]any{"Domains": []any{"private.example.test"}, "DomainAction": "NeverConnect"},
			map[string]any{"Domains": []any{"*.example.test", "*"}, "DomainAction": "ConnectIfNeeded", "RequiredDNSServers": []any{"192.0.2.1", "2001:db8::1"}, "RequiredURLStringProbe": "https://probe.example.test/inside?exact=1"},
		},
	}
}

func TestIKEv2OnDemandPreservesRuleOrderPatternsAndOmissions(t *testing.T) {
	p := vpnSettings("IKEv2")
	c := p["IKEv2"].(map[string]any)
	c["OnDemandEnabled"] = 0
	c["OnDemandRules"] = []any{vpnOnDemandRuleFixture(), map[string]any{"Action": "Allow"}, map[string]any{"Action": "Connect"}, map[string]any{"Action": "Disconnect"}, map[string]any{"Action": "Ignore"}, map[string]any{"Action": "EvaluateConnection"}}
	data, err := plist.Marshal(p, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if _, err = plist.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	before, err := plist.Marshal(decoded, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"System", "User"} {
		if err = validateVPNPayload(decoded, scope, &Device{Model: "Mac16,1", OSVersion: "10.11"}); err != nil {
			t.Fatal(err)
		}
	}
	after, err := plist.Marshal(decoded, plist.XMLFormat)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("on-demand validation changed order, patterns, explicit zero or omissions", err)
	}
	for _, rules := range []any{[]any{}, []any{map[string]any{"Action": "EvaluateConnection", "ActionParameters": []any{}, "DNSDomainMatch": []any{}, "DNSServerAddressMatch": []any{}, "SSIDMatch": []any{}}}} {
		c["OnDemandRules"] = rules
		if err = validateVPNPayload(p, "System", nil); err != nil {
			t.Fatal("explicit empty optional lists rejected", err)
		}
	}
}

func TestIKEv2OnDemandRejectsMalformedAndMisplacedFields(t *testing.T) {
	for _, bad := range []any{nil, true, "synthetic-private-value", map[string]any{}, make([]any, 65), []any{true}, []any{map[string]any{}}, []any{map[string]any{"Action": true}}, []any{map[string]any{"Action": "connect"}}} {
		if err := validateIKEv2OnDemand(map[string]any{"OnDemandEnabled": 0, "OnDemandRules": bad}); err == nil || strings.Contains(err.Error(), "synthetic-private-value") {
			t.Fatal("invalid disabled rules accepted or echoed", err)
		}
	}
	for _, tc := range []struct {
		key   string
		value any
	}{
		{"synthetic-private-value", true}, {"InterfaceTypeMatch", "wifi"}, {"InterfaceTypeMatch", true},
		{"DNSDomainMatch", true}, {"DNSDomainMatch", []any{true}}, {"DNSDomainMatch", []any{strings.Repeat("x", 255)}}, {"DNSDomainMatch", []any{"example.test\n"}},
		{"DNSServerAddressMatch", "192.0.2.1"}, {"DNSServerAddressMatch", []any{true}},
		{"SSIDMatch", true}, {"SSIDMatch", []any{true}}, {"SSIDMatch", []any{""}}, {"SSIDMatch", []any{strings.Repeat("é", 17)}}, {"SSIDMatch", []any{string([]byte{255})}},
		{"URLStringProbe", true}, {"URLStringProbe", "ftp://example.test"}, {"URLStringProbe", "https://user:synthetic-private-value@example.test"}, {"URLStringProbe", "https://example.test/#fragment"}, {"URLStringProbe", "https://example.test:65536"},
		{"ActionParameters", true}, {"ActionParameters", []any{true}}, {"ActionParameters", make([]any, 65)},
	} {
		rule := vpnOnDemandRuleFixture()
		rule[tc.key] = tc.value
		if err := validateIKEv2OnDemand(map[string]any{"OnDemandRules": []any{rule}}); err == nil || strings.Contains(err.Error(), "synthetic-private-value") {
			t.Fatal("invalid rule field accepted or echoed", tc.key, err)
		}
	}
	for _, action := range []string{"Allow", "Connect", "Disconnect", "Ignore"} {
		rule := vpnOnDemandRuleFixture()
		rule["Action"] = action
		if err := validateIKEv2OnDemand(map[string]any{"OnDemandRules": []any{rule}}); err == nil {
			t.Fatal("action parameters accepted for wrong action", action)
		}
	}
	for _, parameter := range []map[string]any{
		{}, {"Domains": []any{"*"}}, {"Domains": []any{}, "DomainAction": "NeverConnect"}, {"Domains": []any{true}, "DomainAction": "NeverConnect"}, {"Domains": []any{"*"}, "DomainAction": true},
		{"Domains": []any{"*"}, "DomainAction": "NeverConnect", "RequiredDNSServers": []any{"192.0.2.1"}},
		{"Domains": []any{"*"}, "DomainAction": "NeverConnect", "RequiredURLStringProbe": "https://example.test"},
		{"Domains": []any{"*"}, "DomainAction": "ConnectIfNeeded", "RequiredDNSServers": []any{}},
		{"Domains": []any{"*"}, "DomainAction": "ConnectIfNeeded", "RequiredDNSServers": []any{true}},
		{"Domains": []any{"*"}, "DomainAction": "ConnectIfNeeded", "RequiredDNSServers": []any{"dns.example.test"}},
		{"Domains": []any{"*"}, "DomainAction": "ConnectIfNeeded", "RequiredDNSServers": []any{"17.*"}},
		{"Domains": []any{"*"}, "DomainAction": "ConnectIfNeeded", "RequiredDNSServers": []any{"192.0.2.1:53"}},
		{"Domains": []any{"*"}, "DomainAction": "ConnectIfNeeded", "RequiredURLStringProbe": "https://example.test/#fragment"},
		{"Domains": []any{"*"}, "DomainAction": "ConnectIfNeeded", "synthetic-private-value": true},
	} {
		rule := vpnOnDemandRuleFixture()
		rule["ActionParameters"] = []any{parameter}
		if err := validateIKEv2OnDemand(map[string]any{"OnDemandRules": []any{rule}}); err == nil || strings.Contains(err.Error(), "synthetic-private-value") {
			t.Fatal("invalid connection evaluation accepted or echoed", err)
		}
	}
}

func TestIKEv2OnDemandChecksAppLayerAndFlatAlwaysOnRules(t *testing.T) {
	for _, kind := range []string{"com.apple.vpn.managed", "com.apple.vpn.managed.applayer", "AlwaysOn"} {
		p := vpnSettings("IKEv2")
		c := p["IKEv2"].(map[string]any)
		if kind == "AlwaysOn" {
			p = vpnSettings("AlwaysOn")
			c = p["AlwaysOn"].(map[string]any)["TunnelConfigurations"].([]any)[0].(map[string]any)
		} else {
			p["PayloadType"] = kind
			p["VPNUUID"] = "11111111-1111-4111-8111-111111111111"
		}
		c["OnDemandRules"] = []any{vpnOnDemandRuleFixture()}
		if err := validateVPNPayload(p, "System", nil); err != nil {
			t.Fatal(err)
		}
		c["OnDemandRules"] = []any{map[string]any{"Action": "synthetic-private-value"}}
		if err := validateVPNPayload(p, "System", nil); err == nil || strings.Contains(err.Error(), "synthetic-private-value") {
			t.Fatal("IKEv2 context bypassed rule validation", kind, err)
		}
	}
}
