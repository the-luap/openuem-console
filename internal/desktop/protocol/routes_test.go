package protocol

import (
	"encoding/base64"
	"net/http/httptest"
	"testing"
)

func TestBootstrapRoutesHaveExactReadOnlyMethodsAndPaths(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	configuration := "/enroll/desktop/" + token + "/configuration"
	keys := "/enroll/desktop/bootstrap-keys"
	for _, path := range []string{configuration, keys} {
		for _, method := range []string{"GET", "HEAD"} {
			if route, ok := Parse(httptest.NewRequest(method, "https://uem.example.test"+path, nil)); !ok || (route.Kind != "configuration" && route.Kind != "bootstrap-keys") {
				t.Fatal("canonical read-only bootstrap route rejected")
			}
		}
		for _, method := range []string{"POST", "PUT", "DELETE", "OPTIONS"} {
			if _, ok := Parse(httptest.NewRequest(method, "https://uem.example.test"+path, nil)); ok {
				t.Fatal("bootstrap route accepted another method")
			}
		}
		for _, suffix := range []string{"/", "/admin", "?", "?origin=other", "#fragment"} {
			if _, ok := Parse(httptest.NewRequest("GET", "https://uem.example.test"+path+suffix, nil)); ok {
				t.Fatal("bootstrap route normalized an ambiguous URL")
			}
		}
	}
	for _, path := range []string{"/enroll/desktop/bootstrap%2Dkeys", "/enroll/desktop/" + token + "/configuratio%6E", "/enroll/desktop/short/configuration"} {
		if _, ok := Parse(httptest.NewRequest("GET", "https://uem.example.test"+path, nil)); ok {
			t.Fatal("bootstrap route accepted an encoded alias or invalid token")
		}
	}
}
