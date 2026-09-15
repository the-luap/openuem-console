package inventory

import (
	"bytes"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestNetbirdRegistrationSecretBindsRequestScopeProviderAndPurpose(t *testing.T) {
	aead, err := registrationCipher(strings.Repeat("k", 32))
	if err != nil {
		t.Fatal(err)
	}
	r := &NetbirdRegistration{ID: "10000000-0000-4000-8000-000000000001", DeviceID: "owned-device", Actor: "owned-actor", Scope: access.Scope{TenantID: 1, SiteID: 2}, Revision: strings.Repeat("a", 64)}
	plain := []byte("owned-private-registration-credential")
	envelope, err := sealRegistration(aead, r, "setup-key", "owned-key", plain)
	if err != nil {
		t.Fatal(err)
	}
	again, err := sealRegistration(aead, r, "setup-key", "owned-key", plain)
	if err != nil || again == envelope {
		t.Fatal("nonce reused", err)
	}
	got, err := openRegistration(aead, r, "setup-key", "owned-key", envelope)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("authenticated round trip failed", err)
	}
	for _, change := range []func(*NetbirdRegistration){
		func(r *NetbirdRegistration) { r.ID = "20000000-0000-4000-8000-000000000001" },
		func(r *NetbirdRegistration) { r.DeviceID = "another-device" },
		func(r *NetbirdRegistration) { r.Actor = "another-actor" },
		func(r *NetbirdRegistration) { r.Scope.TenantID++ },
		func(r *NetbirdRegistration) { r.Scope.SiteID++ },
		func(r *NetbirdRegistration) { r.Individual = true },
		func(r *NetbirdRegistration) { r.Revision = strings.Repeat("b", 64) },
	} {
		copy := *r
		change(&copy)
		if _, err = openRegistration(aead, &copy, "setup-key", "owned-key", envelope); err == nil {
			t.Fatal("envelope accepted different authority")
		}
	}
	for _, input := range [][3]string{{"provider", "owned-key", envelope}, {"setup-key", "other-key", envelope}, {"setup-key", "owned-key", string(plain)}, {"setup-key", "owned-key", strings.Replace(envelope, ":v1:", ":v2:", 1)}, {"setup-key", "owned-key", envelope[:len(envelope)-2] + "AA"}, {"setup-key", "owned-key", strings.Repeat("a", 45001)}} {
		if _, err = openRegistration(aead, r, input[0], input[1], input[2]); err == nil {
			t.Fatal("invalid credential authenticated")
		}
	}
	other, _ := registrationCipher(strings.Repeat("j", 32))
	if _, err = openRegistration(other, r, "setup-key", "owned-key", envelope); err == nil {
		t.Fatal("wrong master key authenticated")
	}
	if _, err = registrationCipher("short"); err == nil {
		t.Fatal("weak master key accepted")
	}
}
