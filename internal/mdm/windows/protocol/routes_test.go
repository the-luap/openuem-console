package protocol

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestExactWindowsPublicRoutes(t *testing.T) {
	for _, path := range []string{DiscoveryPath, PolicyPath, EnrollmentPath, ManagementPath} {
		for _, method := range []string{"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"} {
			r := httptest.NewRequest(method, "https://uem.example.test"+path, nil)
			want := method == "POST" || path == DiscoveryPath && (method == "GET" || method == "HEAD")
			if Public(r) != want {
				t.Fatal("incorrect public method", method, path)
			}
		}
		for _, change := range []func(*http.Request){
			func(r *http.Request) { r.URL.Path += "/" },
			func(r *http.Request) { r.URL.Path += "/admin" },
			func(r *http.Request) { r.URL.RawPath = path },
			func(r *http.Request) { r.URL.RawQuery = "tenant=2" },
			func(r *http.Request) { r.URL.ForceQuery = true },
			func(r *http.Request) { r.URL.Fragment = "private" },
			func(r *http.Request) { r.URL.RawFragment = "private" },
			func(r *http.Request) { r.URL.User = url.User("admin") },
			func(r *http.Request) { r.URL.Opaque = "//uem.example.test" + path },
			func(r *http.Request) { r.URL.Scheme = "http" },
			func(r *http.Request) { r.URL.Host = "other.example.test" },
			func(r *http.Request) { r.URL = nil },
		} {
			r := httptest.NewRequest("POST", "https://uem.example.test"+path, nil)
			change(r)
			if Path(r) != "" || Public(r) {
				t.Fatal("noncanonical route admitted")
			}
		}
	}
	if Path(nil) != "" || Public(nil) {
		t.Fatal("nil request admitted")
	}
}
