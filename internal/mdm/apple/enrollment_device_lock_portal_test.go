package apple

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"
)

func TestEnrollmentDeviceLockPortalRequiresOwnerConfirmation(t *testing.T) {
	s, server, invite, token := portalFixture(t, EnrollmentOptions{AllowMacDeviceLock: true})
	client := server.Client()
	form := portalStart(t, client, invite.URL)
	form.Set("platform", "macos")
	for _, test := range []struct {
		name   string
		change func(url.Values)
		status int
	}{
		{"missing confirmation", func(f url.Values) { f.Del("confirm_device_lock") }, 400},
		{"wrong confirmation", func(f url.Values) { f.Set("confirm_device_lock", "no") }, 400},
		{"duplicate confirmation", func(f url.Values) { f["confirm_device_lock"] = []string{"yes", "no"} }, 400},
		{"wrong platform", func(f url.Values) { f.Set("platform", "ios") }, 400},
		{"duplicate platform", func(f url.Values) { f.Add("platform", "ipados") }, 400},
		{"duplicate enrollment confirmation", func(f url.Values) { f.Add("confirm", "no") }, 400},
		{"duplicate action", func(f url.Values) { f.Add("action", "download") }, 400},
		{"wrong csrf", func(f url.Values) { f.Set("csrf", "wrong") }, 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := url.Values{}
			for key, values := range form {
				copy[key] = append([]string(nil), values...)
			}
			copy.Set("confirm_device_lock", "yes")
			test.change(copy)
			response := portalPost(t, client, invite.URL, server.URL, copy)
			portalRead(t, response)
			if response.StatusCode != test.status {
				t.Fatal("unsafe claim accepted", response.StatusCode)
			}
			var ready bool
			if err := s.db.QueryRow(`SELECT status='pending' AND invite_hash IS NOT NULL FROM mdm_apple_devices WHERE id=$1`, invite.DeviceID).Scan(&ready); err != nil || !ready {
				t.Fatal("rejected form consumed invitation", err)
			}
		})
	}
	form.Set("confirm_device_lock", "yes")
	for i := 0; i < 2; i++ {
		response := portalPost(t, client, invite.URL, server.URL, form)
		portalRead(t, response)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatal("confirmed Mac claim or retry rejected", response.StatusCode)
		}
	}
	download := url.Values{"csrf": form["csrf"], "action": {"download"}}
	response := portalPost(t, client, invite.URL, server.URL, download)
	profile := portalRead(t, response)
	if response.StatusCode != 200 || numberValue(testEnrollmentMDMPayload(t, profile)["AccessRights"]) != 7959 {
		t.Fatal("confirmed download missing exact rights", response.StatusCode)
	}
	response = portalPost(t, client, invite.URL, server.URL, download)
	if copy := portalRead(t, response); !bytes.Equal(profile, copy) {
		t.Fatal("download retry changed rights or profile")
	}
	otherBrowser, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	status, err := s.EnrollmentStatus(t.Context(), token, otherBrowser)
	if err != nil || status.State != "used" || status.DeviceLockAllowed || status.Organization != "" {
		t.Fatal("other browser learned invitation options", err)
	}
}

func TestEnrollmentDeviceLockCannotBeAddedByPublicForm(t *testing.T) {
	s, server, invite, _ := portalFixture(t)
	client := server.Client()
	form := portalStart(t, client, invite.URL)
	form.Set("platform", "macos")
	form.Set("allow_mac_device_lock", "yes")
	form.Set("confirm_device_lock", "yes")
	response := portalPost(t, client, invite.URL, server.URL, form)
	portalRead(t, response)
	if response.StatusCode != http.StatusSeeOther {
		t.Fatal("baseline Mac claim failed", response.StatusCode)
	}
	response = portalPost(t, client, invite.URL, server.URL, url.Values{"csrf": form["csrf"], "action": {"download"}})
	profile := portalRead(t, response)
	if response.StatusCode != 200 || numberValue(testEnrollmentMDMPayload(t, profile)["AccessRights"]) != 7955 {
		t.Fatal("browser escalated invitation rights")
	}
	var allowed bool
	if err := s.db.QueryRow(`SELECT device_lock_allowed FROM mdm_apple_devices WHERE id=$1`, invite.DeviceID).Scan(&allowed); err != nil || allowed {
		t.Fatal("browser changed stored rights", err)
	}
}
