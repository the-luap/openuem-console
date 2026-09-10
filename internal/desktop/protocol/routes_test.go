package protocol

import (
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment"
)

func TestBootstrapRoutesHaveExactReadOnlyMethodsAndPaths(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	configuration := "/enroll/desktop/" + token + "/configuration"
	keys := "/enroll/desktop/bootstrap-keys"
	for _, path := range []string{configuration, keys, "/enroll/desktop/" + token, "/enroll/desktop/" + token + "/invitation"} {
		for _, method := range []string{"GET", "HEAD"} {
			if _, ok := Parse(httptest.NewRequest(method, "https://uem.example.test"+path, nil)); !ok {
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

func TestIdentityRenewalRoutesRequireExactDeviceOperationAndPOST(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	for _, operation := range []string{"prepare", "confirm"} {
		path := enrollment.IdentityRenewalPath(id, operation)
		route, ok := Parse(httptest.NewRequest("POST", "https://uem.example.test"+path, nil))
		if !ok || route.Kind != "renewal-"+operation || route.DeviceID != id || route.Token != "" {
			t.Fatal("canonical renewal route was not identified")
		}
		for _, method := range []string{"GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"} {
			if _, ok := Parse(httptest.NewRequest(method, "https://uem.example.test"+path, nil)); ok {
				t.Fatal("renewal accepted another method")
			}
		}
		for _, invalid := range []string{path + "/", path + "/admin", path + "?", path + "?device=other", path + "#fragment", strings.Replace(path, "identities", "identit%69es", 1), strings.Replace(path, id, "invalid", 1), strings.Replace(path, "/renewal/", "//renewal/", 1)} {
			if _, ok := Parse(httptest.NewRequest("POST", "https://uem.example.test"+invalid, nil)); ok {
				t.Fatal("renewal accepted a noncanonical path", invalid)
			}
		}
	}
	if path := enrollment.IdentityRenewalPath(id, "status"); path != "" {
		t.Fatal("unimplemented operation obtained a route")
	}
}
