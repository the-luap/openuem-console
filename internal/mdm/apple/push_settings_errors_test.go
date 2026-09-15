package apple

import (
	"errors"
	"strings"
	"testing"
)

func TestPushOrganizationValidationHasStablePublicIdentity(t *testing.T) {
	for _, tc := range []struct {
		settings Settings
		want     error
	}{
		{Settings{PublicURL: "https://mdm.example.test", Organization: "Example"}, ErrPushOrganization},
		{Settings{TenantID: 1, PublicURL: "https://user:private@mdm.example.test", Organization: "Example"}, ErrPushPublicURL},
		{Settings{TenantID: 1, PublicURL: "https://mdm.example.test"}, ErrPushOrganizationName},
		{Settings{TenantID: 1, PublicURL: "https://mdm.example.test", Organization: strings.Repeat("x", 256)}, ErrPushOrganizationName},
		{Settings{TenantID: 1, PublicURL: "https://mdm.example.test/", Organization: "Example"}, nil},
	} {
		err := validatePushOrganization(&tc.settings)
		if !errors.Is(err, tc.want) {
			t.Fatal("push validation lost its stable public error", err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), "private") {
			t.Fatal("public validation returned supplied credentials")
		}
		if err == nil && tc.settings.PublicURL != "https://mdm.example.test" {
			t.Fatal("valid public origin lost normalization")
		}
	}
}
