package apple

import (
	"testing"

	"github.com/google/uuid"
	"howett.net/plist"
)

func TestExtensibleSSODuplicateRoutingRejectedAcrossUploadedPayloads(t *testing.T) {
	settings := platformSSOSettings()
	p := platformSSOProfile(t, settings)
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		t.Fatal(err)
	}
	second := map[string]any{"PayloadType": "com.apple.extensiblesso", "PayloadIdentifier": "com.example.other.sso", "PayloadUUID": uuid.NewString(), "PayloadVersion": 1, "Type": "Redirect", "ExtensionIdentifier": "com.example.Other.extension", "TeamIdentifier": "ABCDEFGHIJ", "URLs": []any{"HTTPS://LOGIN.EXAMPLE.TEST/"}}
	root["PayloadContent"] = append(root["PayloadContent"].([]any), second)
	data, err := plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseProfile(data); err == nil {
		t.Fatal("uploaded profile accepted duplicate URLs in separate SSO payloads")
	}
	second["URLs"] = []any{"https://other.example.test/"}
	data, err = plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseProfile(data); err != nil {
		t.Fatal("distinct SSO providers were rejected", err)
	}
}
