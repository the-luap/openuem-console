package apple

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func TestAlwaysOnExceptionValuesSurvivePlistValidation(t *testing.T) {
	p := vpnSettings("AlwaysOn")
	a := p["AlwaysOn"].(map[string]any)
	a["ServiceExceptions"] = []any{
		map[string]any{"ServiceName": "VoiceMail", "Action": "Drop"},
		map[string]any{"ServiceName": "AirPrint", "Action": "Allow"},
		map[string]any{"ServiceName": "CellularServices", "Action": "Drop"},
		map[string]any{"ServiceName": "DeviceCommunication", "Action": "Allow"},
	}
	a["ApplicationExceptions"] = []any{
		map[string]any{"BundleIdentifier": "com.example.Unrestricted"},
		map[string]any{"BundleIdentifier": "com.example.UDP-Only2", "LimitToProtocols": []any{"UDP"}},
	}
	a["AllowedCaptiveNetworkPlugins"] = []any{map[string]any{"BundleIdentifier": "com.example.Captive"}}
	a["AllowAllCaptiveNetworkPlugins"] = 0
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
	now := time.Now()
	for _, model := range []string{"iPhone16,1", "iPad14,3"} {
		d := &Device{Model: model, OSVersion: "17.4", Supervised: true, SupervisedReported: true, InventoryAt: &now}
		if err = validateVPNPayload(decoded, "System", d); err != nil {
			t.Fatal(err)
		}
	}
	after, err := plist.Marshal(decoded, plist.XMLFormat)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("validation changed explicit exception values", err)
	}
	// Apple ignores the specific captive list when all plugins are allowed.
	// Retain a valid list without turning off the explicitly requested broad flag.
	a["AllowAllCaptiveNetworkPlugins"] = 1
	if err = validateVPNPayload(p, "System", nil); err != nil {
		t.Fatal(err)
	}
	if a["AllowAllCaptiveNetworkPlugins"] != 1 {
		t.Fatal("validation narrowed an explicit captive exception")
	}
}

func TestAlwaysOnExceptionVersionBoundaries(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name, key, below, at string
		value                any
	}{
		{"cellular", "ServiceExceptions", "11.2.6", "11.3", []any{map[string]any{"ServiceName": "CellularServices", "Action": "Drop"}}},
		{"device communication", "ServiceExceptions", "17.3.1", "17.4", []any{map[string]any{"ServiceName": "DeviceCommunication", "Action": "Allow"}}},
		{"app", "ApplicationExceptions", "13.5.1", "13.6", []any{map[string]any{"BundleIdentifier": "com.example.App", "LimitToProtocols": []any{"UDP"}}}},
		{"empty app list", "ApplicationExceptions", "13.5.1", "13.6", []any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := vpnSettings("AlwaysOn")
			p["AlwaysOn"].(map[string]any)[tc.key] = tc.value
			for _, model := range []string{"iPhone16,1", "iPad14,3"} {
				d := &Device{Model: model, OSVersion: tc.below, Supervised: true, SupervisedReported: true, InventoryAt: &now}
				if err := validateVPNPayload(p, "System", d); err == nil {
					t.Fatal("exception reached unsupported OS", model)
				}
				d.OSVersion = tc.at
				if err := validateVPNPayload(p, "System", d); err != nil {
					t.Fatal("exception rejected at its boundary", err)
				}
			}
		})
	}
	for _, key := range []string{"ServiceExceptions", "AllowedCaptiveNetworkPlugins"} {
		p := vpnSettings("AlwaysOn")
		p["AlwaysOn"].(map[string]any)[key] = []any{}
		if err := validateVPNPayload(p, "System", &Device{Model: "iPhone16,1", OSVersion: "8.0", Supervised: true, SupervisedReported: true, InventoryAt: &now}); err != nil {
			t.Fatal("empty original list changed baseline", err)
		}
	}
}

func TestAlwaysOnExceptionTypesAmbiguityAndAdmissionBounds(t *testing.T) {
	for _, key := range []string{"ServiceExceptions", "ApplicationExceptions", "AllowedCaptiveNetworkPlugins"} {
		for _, bad := range []any{nil, true, "synthetic-private-value", map[string]any{}, []any{true}, []any{map[string]any{}}, make([]any, 65)} {
			p := vpnSettings("AlwaysOn")
			p["AlwaysOn"].(map[string]any)[key] = bad
			if err := validateVPNPayload(p, "System", nil); err == nil || strings.Contains(err.Error(), "synthetic-private-value") {
				t.Fatal("invalid or oversized exception list admitted", key, err)
			}
		}
	}
	for _, entry := range []map[string]any{
		{"ServiceName": "VoiceMail"}, {"ServiceName": "Voicemail", "Action": "Allow"},
		{"ServiceName": true, "Action": "Allow"}, {"ServiceName": "AirPrint", "Action": true},
		{"ServiceName": "CellularServices", "Action": "allow"}, {"ServiceName": "AirPrint", "Action": "Allow", "synthetic-private-value": true},
	} {
		p := vpnSettings("AlwaysOn")
		p["AlwaysOn"].(map[string]any)["ServiceExceptions"] = []any{entry}
		if err := validateVPNPayload(p, "System", nil); err == nil || strings.Contains(err.Error(), "synthetic-private-value") {
			t.Fatal("invalid service exception admitted", err)
		}
	}
	p := vpnSettings("AlwaysOn")
	a := p["AlwaysOn"].(map[string]any)
	a["ServiceExceptions"] = []any{map[string]any{"ServiceName": "AirPrint", "Action": "Allow"}, map[string]any{"ServiceName": "AirPrint", "Action": "Drop"}}
	if err := validateVPNPayload(p, "System", nil); err == nil {
		t.Fatal("conflicting service actions admitted")
	}
	delete(a, "ServiceExceptions")
	for _, key := range []string{"ApplicationExceptions", "AllowedCaptiveNetworkPlugins"} {
		for _, id := range []any{true, "", "com.example.*", "com.example.App ", "com.example.Äpp", "com..example", "com.example." + strings.Repeat("a", 244)} {
			a[key] = []any{map[string]any{"BundleIdentifier": id}}
			if err := validateVPNPayload(p, "System", nil); err == nil {
				t.Fatal("invalid bundle exception admitted", key)
			}
		}
		a[key] = []any{map[string]any{"BundleIdentifier": "com.example.App"}, map[string]any{"BundleIdentifier": "COM.EXAMPLE.APP"}}
		if err := validateVPNPayload(p, "System", nil); err == nil {
			t.Fatal("duplicate bundle exception admitted", key)
		}
		list := []any{}
		for i := range 64 {
			list = append(list, map[string]any{"BundleIdentifier": fmt.Sprintf("com.example.App%d", i)})
		}
		a[key] = list
		if err := validateVPNPayload(p, "System", nil); err != nil {
			t.Fatal("valid maximum exception list rejected", err)
		}
		delete(a, key)
	}
	for _, protocols := range []any{nil, true, "UDP", []any{}, []any{"TCP"}, []any{"udp"}, []any{"UDP", "UDP"}, []any{true}, []any{map[string]any{}}} {
		a["ApplicationExceptions"] = []any{map[string]any{"BundleIdentifier": "com.example.App", "LimitToProtocols": protocols}}
		if err := validateVPNPayload(p, "System", nil); err == nil {
			t.Fatal("invalid UDP limit admitted")
		}
	}
	delete(a, "ApplicationExceptions")
	a["AllowAllCaptiveNetworkPlugins"] = 1
	a["AllowedCaptiveNetworkPlugins"] = []any{map[string]any{"BundleIdentifier": "com.example.Captive", "LimitToProtocols": []any{"UDP"}}}
	if err := validateVPNPayload(p, "System", nil); err == nil {
		t.Fatal("ignored captive list bypassed known schema")
	}
}
