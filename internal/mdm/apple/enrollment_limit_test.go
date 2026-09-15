package apple

import (
	"net/http/httptest"
	"testing"

	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

func TestEnrollmentRateLimitsDoNotTrustDirectForwardedAddresses(t *testing.T) {
	l := newEnrollmentLimiter()
	r := httptest.NewRequest("GET", "https://mdm.example.test", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	for i := 0; i < 30; i++ {
		if !l.allow(r, clientidentity.Policy{}) {
			t.Fatal("initial browser burst denied", i)
		}
	}
	r.Header.Set("X-Forwarded-For", "203.0.113.2")
	if l.allow(r, clientidentity.Policy{}) {
		t.Fatal("untrusted forwarding bypassed source rate limit")
	}
	r.RemoteAddr = "192.0.2.2:1234"
	if !l.allow(r, clientidentity.Policy{}) {
		t.Fatal("unrelated device source was denied")
	}
	for _, value := range []string{"no-address", "[fe80::1%eth0]:1234"} {
		r.RemoteAddr = value
		if l.allow(r, clientidentity.Policy{}) {
			t.Fatal("invalid source accepted", value)
		}
	}
	l = newEnrollmentLimiter()
	r.RemoteAddr = "[2001:db8::1]:1234"
	for i := 0; i < 30; i++ {
		if !l.allow(r, clientidentity.Policy{}) {
			t.Fatal("initial IPv6 burst denied", i)
		}
	}
	r.RemoteAddr = "[2001:db8::2]:1234"
	if l.allow(r, clientidentity.Policy{}) {
		t.Fatal("another address within IPv6 /64 bypassed limit")
	}
	r.RemoteAddr = "[2001:db8:0:1::1]:1234"
	if !l.allow(r, clientidentity.Policy{}) {
		t.Fatal("different IPv6 network blocked")
	}
}
