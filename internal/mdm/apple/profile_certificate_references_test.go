package apple

import (
	"strings"
	"testing"

	"howett.net/plist"
)

func referenceFixture() (map[string]any, map[string]any, map[string]any, map[string]any) {
	identity := map[string]any{"PayloadType": "com.apple.security.scep", "PayloadUUID": "aaaaaaaa-0000-4000-8000-000000000001"}
	anchor := map[string]any{"PayloadType": "com.apple.security.root", "PayloadUUID": "bbbbbbbb-0000-4000-8000-000000000002"}
	wifi := map[string]any{"PayloadType": "com.apple.wifi.managed", "PayloadUUID": "cccccccc-0000-4000-8000-000000000003", "PayloadCertificateUUID": identity["PayloadUUID"], "EAPClientConfiguration": map[string]any{"AcceptEAPTypes": []any{uint64(13)}, "PayloadCertificateAnchorUUID": []any{anchor["PayloadUUID"]}}}
	root := map[string]any{"PayloadUUID": "dddddddd-0000-4000-8000-000000000004", "PayloadContent": []any{wifi, identity, anchor}}
	return root, wifi, identity, anchor
}

func TestCertificateReferencesResolveOnlyMatchingLocalPayloads(t *testing.T) {
	for _, kind := range []string{"com.apple.security.scep", "com.apple.security.acme", "com.apple.security.pkcs12", "com.apple.ADCertificate.managed"} {
		root, wifi, identity, _ := referenceFixture()
		identity["PayloadType"] = kind
		wifi["PayloadCertificateUUID"] = strings.ToUpper(identity["PayloadUUID"].(string))
		if err := validateProfileCertificateReferences(root); err != nil {
			t.Fatal(kind, err)
		}
		data, err := plist.Marshal(root, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if _, err = plist.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if err = validateProfileCertificateReferences(decoded); err != nil {
			t.Fatal("wire reference changed", err)
		}
	}
	for _, kind := range []string{"com.apple.security.root", "com.apple.security.pem", "com.apple.security.pkcs1"} {
		root, _, _, anchor := referenceFixture()
		anchor["PayloadType"] = kind
		if err := validateProfileCertificateReferences(root); err != nil {
			t.Fatal(kind, err)
		}
	}
	root, wifi, _, _ := referenceFixture()
	delete(wifi, "PayloadCertificateUUID")
	delete(wifi, "EAPClientConfiguration")
	if err := validateProfileCertificateReferences(root); err != nil {
		t.Fatal("ordinary Wi-Fi requires no certificate", err)
	}
}

func TestCertificateReferencesRejectMissingWrongAndAmbiguousCredentials(t *testing.T) {
	for _, change := range []func(map[string]any, map[string]any, map[string]any, map[string]any){
		func(r, w, i, a map[string]any) { w["PayloadCertificateUUID"] = r["PayloadUUID"] },
		func(r, w, i, a map[string]any) { w["PayloadCertificateUUID"] = "eeeeeeee-0000-4000-8000-000000000005" },
		func(r, w, i, a map[string]any) { w["PayloadCertificateUUID"] = a["PayloadUUID"] },
		func(r, w, i, a map[string]any) { w["PayloadCertificateUUID"] = "com.example.identity" },
		func(r, w, i, a map[string]any) { w["PayloadCertificateUUID"] = true },
		func(r, w, i, a map[string]any) { w["PayloadCertificateUUID"] = "urn:uuid:" + i["PayloadUUID"].(string) },
		func(r, w, i, a map[string]any) { i["PayloadUUID"] = "{aaaaaaaa-0000-4000-8000-000000000001}" },
		func(r, w, i, a map[string]any) { i["PayloadType"] = "com.apple.mdm" },
		func(r, w, i, a map[string]any) { a["PayloadUUID"] = strings.ToUpper(i["PayloadUUID"].(string)) },
		func(r, w, i, a map[string]any) { r["PayloadContent"] = append(r["PayloadContent"].([]any), i) },
		func(r, w, i, a map[string]any) { w["EAPClientConfiguration"] = "synthetic-private-value" },
		func(r, w, i, a map[string]any) {
			w["EAPClientConfiguration"].(map[string]any)["PayloadCertificateAnchorUUID"] = a["PayloadUUID"]
		},
		func(r, w, i, a map[string]any) {
			w["EAPClientConfiguration"].(map[string]any)["PayloadCertificateAnchorUUID"] = []any{}
		},
		func(r, w, i, a map[string]any) {
			w["EAPClientConfiguration"].(map[string]any)["PayloadCertificateAnchorUUID"] = []any{i["PayloadUUID"]}
		},
		func(r, w, i, a map[string]any) {
			w["EAPClientConfiguration"].(map[string]any)["PayloadCertificateAnchorUUID"] = []any{a["PayloadUUID"], strings.ToUpper(a["PayloadUUID"].(string))}
		},
	} {
		root, wifi, identity, anchor := referenceFixture()
		change(root, wifi, identity, anchor)
		if err := validateProfileCertificateReferences(root); err == nil || strings.Contains(err.Error(), "synthetic-private-value") {
			t.Fatal("invalid certificate binding accepted or value echoed", err)
		}
	}
}
