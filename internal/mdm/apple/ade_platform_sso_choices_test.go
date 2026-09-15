package apple

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"howett.net/plist"
)

func TestADEPlatformSSOChoicesBoundedCurrentPrivateAndTenantScoped(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	var root map[string]any
	if _, err := plist.Unmarshal(adeSSOPayload(t, true, false), &root); err != nil {
		t.Fatal(err)
	}
	var first *Profile
	for i := range 27 {
		root["PayloadDisplayName"] = fmt.Sprintf("Picker profile %02d", i)
		root["PayloadIdentifier"] = fmt.Sprintf("com.example.picker.%02d", i)
		data, err := plist.Marshal(root, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
		p, err := s.SaveProfile(t.Context(), 1, "", 0, data, "admin")
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = p
		}
	}
	page, next, err := s.ADEPlatformSSOChoices(t.Context(), 1, "Picker", "")
	if err != nil || len(page) != 25 || next == "" {
		t.Fatal("unbounded or missing first page", err)
	}
	last, end, err := s.ADEPlatformSSOChoices(t.Context(), 1, "Picker", next)
	if err != nil || len(last) != 2 || end != "" {
		t.Fatal("incorrect last page", err)
	}
	seen := map[string]bool{}
	for _, item := range append(page, last...) {
		if seen[item.ProfileID] || !item.Eligible || item.ID == item.ProfileID {
			t.Fatal("ambiguous or unavailable snapshot selection")
		}
		seen[item.ProfileID] = true
	}
	encoded, _ := json.Marshal(page)
	for _, secret := range []string{"synthetic-provider-token", "RegistrationToken", "PayloadContent", "ExtensionData"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("picker exposed protected profile data")
		}
	}
	for _, query := range []string{"%", "_", `\`} {
		items, _, err := s.ADEPlatformSSOChoices(t.Context(), 1, query, "")
		if err != nil || len(items) != 0 {
			t.Fatal("search interpreted literal wildcard", err)
		}
	}
	for _, query := range []string{strings.Repeat("x", 129), "\x00"} {
		if _, _, err = s.ADEPlatformSSOChoices(t.Context(), 1, query, ""); !errors.Is(err, ErrADEPlatformSSO) {
			t.Fatal("invalid search accepted")
		}
	}
	if _, _, err = s.ADEPlatformSSOChoices(t.Context(), 2, "", next); !errors.Is(err, ErrNotFound) {
		t.Fatal("cursor crossed organization")
	}
	if _, _, err = s.ADEPlatformSSOChoices(t.Context(), 1, "", uuid.NewString()); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown cursor accepted")
	}
	items, _, err := s.ADEPlatformSSOChoices(t.Context(), 2, "", "")
	if err != nil || len(items) != 0 {
		t.Fatal("catalog crossed organization", err)
	}
	old, _, err := s.ADEPlatformSSOChoices(t.Context(), 1, first.Identifier, "")
	if err != nil || len(old) != 1 {
		t.Fatal(err)
	}
	// The picker changes to the latest revision; the previous selected snapshot survives.
	if _, err = s.SaveProfile(t.Context(), 1, first.ID, 1, first.Payload, "admin"); err != nil {
		t.Fatal(err)
	}
	current, _, err := s.ADEPlatformSSOChoices(t.Context(), 1, first.Identifier, "")
	if err != nil || len(current) != 1 || current[0].ID == old[0].ID || !strings.HasSuffix(current[0].Label, "Revision 2") {
		t.Fatal("picker retained an obsolete catalog revision", err)
	}
	if _, err = s.ProfileRevisionPayload(t.Context(), 1, old[0].ID); err != nil {
		t.Fatal("selected snapshot disappeared", err)
	}
	ordinary := platformSSOProfile(t, platformSSOSettings())
	if _, err = s.SaveProfile(t.Context(), 1, "", 0, ordinary.Payload, "admin"); err != nil {
		t.Fatal(err)
	}
	items, _, err = s.ADEPlatformSSOChoices(t.Context(), 1, ordinary.Identifier, "")
	if err != nil || len(items) != 1 || items[0].Eligible {
		t.Fatal("ordinary SSO profile advertised as unattended", err)
	}
	if _, err = s.SaveProfile(t.Context(), 1, "", 0, revisionWiFi(t, "Picker network", "private-network"), "admin"); err != nil {
		t.Fatal(err)
	}
	items, _, err = s.ADEPlatformSSOChoices(t.Context(), 1, "Picker network", "")
	if err != nil || len(items) != 0 {
		t.Fatal("unrelated profile exposed as SSO", err)
	}
}
