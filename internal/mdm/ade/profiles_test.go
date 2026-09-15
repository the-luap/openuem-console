package ade

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testEnrollmentProfile() EnrollmentProfile {
	return EnrollmentProfile{Name: "Synthetic Mac enrollment", URL: "https://mdm.example.test/mdm/apple/ade/synthetic-selector", Supervised: true, Mandatory: true, AwaitDeviceConfigured: true, AllowPairing: true, Department: "Engineering", SupportEmail: "support@example.test", SkipSetupItems: []string{"AppleID", "Siri"}}
}

func TestEnrollmentProfileClientRoutesAndPerDeviceOutcomes(t *testing.T) {
	const profileID = "1234567890ABCDEF1234567890ABCDEF"
	profile := testEnrollmentProfile()
	var mutations atomic.Int32
	c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/session" {
			fmt.Fprint(w, `{"auth_session_token":"synthetic-session"}`)
			return
		}
		if r.Header.Get("X-ADM-Auth-Session") != "synthetic-session" || r.Header.Get("X-Server-Protocol-Version") != "10" {
			t.Error("missing enrollment authentication")
		}
		switch r.Method + " " + r.URL.Path {
		case "POST /profile":
			mutations.Add(1)
			var fields map[string]json.RawMessage
			body, _ := io.ReadAll(r.Body)
			if decodeJSON(body, &fields) != nil {
				t.Error("invalid definition")
			}
			if _, ok := fields["devices"]; ok {
				t.Error("profile definition assigned devices")
			}
			var got EnrollmentProfile
			if decodeJSON(body, &got) != nil || !reflect.DeepEqual(got, profile) {
				t.Error("definition changed")
			}
			fmt.Fprintf(w, `{"profile_uuid":%q,"devices":{}}`, profileID)
		case "GET /profile":
			if r.URL.Query().Get("profile_uuid") != profileID || len(r.URL.Query()) != 1 {
				t.Error("wrong profile selector")
			}
			_ = json.NewEncoder(w).Encode(profile)
		case "POST /profile/devices", "DELETE /profile/devices":
			mutations.Add(1)
			var got struct {
				ID      string   `json:"profile_uuid"`
				Devices []string `json:"devices"`
			}
			if json.NewDecoder(r.Body).Decode(&got) != nil || !reflect.DeepEqual(got.Devices, []string{"SYNTHETIC123", "SYNTHETIC124"}) {
				t.Error("assignment targets changed")
			}
			if r.Method == "POST" {
				if got.ID != profileID {
					t.Error("wrong assignment profile")
				}
				fmt.Fprintf(w, `{"profile_uuid":%q,"devices":{"SYNTHETIC123":"SUCCESS","SYNTHETIC124":"THROTTLED"},"retry_after_seconds":3601}`, profileID)
			} else {
				if got.ID != "" {
					t.Error("clear request contains a profile")
				}
				fmt.Fprint(w, `{"devices":{"SYNTHETIC123":"SUCCESS","SYNTHETIC124":"NOT_ACCESSIBLE"}}`)
			}
		case "POST /devices":
			fmt.Fprintf(w, `{"devices":{"SYNTHETIC123":{"serial_number":"SYNTHETIC123","response_status":"SUCCESS","profile_uuid":%q,"profile_status":"assigned","device_family":"Mac"},"SYNTHETIC124":{"response_status":"NOT_ACCESSIBLE"}}}`, profileID)
		default:
			t.Error("unexpected enrollment API route")
			w.WriteHeader(404)
		}
	})
	id, err := c.DefineProfile(t.Context(), profile)
	if err != nil || id != profileID {
		t.Fatal("definition failed", err)
	}
	got, err := c.Profile(t.Context(), id)
	if err != nil || !reflect.DeepEqual(got, profile) {
		t.Fatal("profile retrieval failed", err)
	}
	result, err := c.AssignProfile(t.Context(), id, []string{"SYNTHETIC123", "SYNTHETIC124"})
	if err != nil || result.Devices["SYNTHETIC123"] != "SUCCESS" || result.Devices["SYNTHETIC124"] != "THROTTLED" || result.RetryAfter != 3601*time.Second {
		t.Fatal("partial assignment or backoff lost", err)
	}
	result, err = c.ClearProfile(t.Context(), []string{"SYNTHETIC123", "SYNTHETIC124"})
	if err != nil || result.Devices["SYNTHETIC124"] != "NOT_ACCESSIBLE" || result.RetryAfter != 0 {
		t.Fatal("clear outcome changed", err)
	}
	details, err := c.DeviceDetails(t.Context(), []string{"SYNTHETIC123", "SYNTHETIC124", "SYNTHETIC125"})
	if err != nil || details["SYNTHETIC123"].ProfileID != id || details["SYNTHETIC124"].ResponseStatus != "NOT_ACCESSIBLE" || len(details) != 2 {
		t.Fatal("current ownership lookup changed", err)
	}
	if mutations.Load() != 3 {
		t.Fatal("remote mutation replayed")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", profile, profile), "synthetic-selector") {
		t.Fatal("profile diagnostics exposed selector")
	}
}

func TestEnrollmentProfileInputsFailBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) })
	for name, change := range map[string]func(*EnrollmentProfile){
		"empty name":           func(p *EnrollmentProfile) { p.Name = "" },
		"long name":            func(p *EnrollmentProfile) { p.Name = strings.Repeat("a", 126) },
		"whitespace":           func(p *EnrollmentProfile) { p.Department = " Team " },
		"control":              func(p *EnrollmentProfile) { p.SupportPhone = "123\n456" },
		"email":                func(p *EnrollmentProfile) { p.SupportEmail = "Admin <admin@example.test>" },
		"insecure callback":    func(p *EnrollmentProfile) { p.URL = "http://mdm.example.test/enroll" },
		"callback credentials": func(p *EnrollmentProfile) { p.URL = "https://user:password@mdm.example.test/enroll" },
		"callback query":       func(p *EnrollmentProfile) { p.URL += "?foo=bar" },
		"callback fragment":    func(p *EnrollmentProfile) { p.URL += "#fragment" },
		"unsupervised lock":    func(p *EnrollmentProfile) { p.Supervised = false },
		"unknown pane":         func(p *EnrollmentProfile) { p.SkipSetupItems = []string{"NotASetupPane"} },
		"duplicate pane":       func(p *EnrollmentProfile) { p.SkipSetupItems = []string{"Siri", "Siri"} },
	} {
		t.Run(name, func(t *testing.T) {
			p := testEnrollmentProfile()
			change(&p)
			if _, err := c.DefineProfile(t.Context(), p); !errors.Is(err, ErrService) {
				t.Fatal("invalid definition accepted")
			}
		})
	}
	for _, serials := range [][]string{nil, {"bad"}, {"SYNTHETIC123", "SYNTHETIC123"}, make([]string, PageLimit+1)} {
		if _, err := c.AssignProfile(t.Context(), "PROFILE1", serials); !errors.Is(err, ErrService) {
			t.Fatal("invalid targets assigned")
		}
		if _, err := c.ClearProfile(t.Context(), serials); !errors.Is(err, ErrService) {
			t.Fatal("invalid targets cleared")
		}
		if _, err := c.DeviceDetails(t.Context(), serials); !errors.Is(err, ErrService) {
			t.Fatal("invalid targets looked up")
		}
	}
	for _, id := range []string{"", "profile?other=value", "../profile", strings.Repeat("a", 129)} {
		if _, err := c.Profile(t.Context(), id); !errors.Is(err, ErrService) {
			t.Fatal("invalid profile read")
		}
		if _, err := c.AssignProfile(t.Context(), id, []string{"SYNTHETIC123"}); !errors.Is(err, ErrService) {
			t.Fatal("invalid profile assigned")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid enrollment input reached remote service")
	}
	p := testEnrollmentProfile()
	p.Name = strings.Repeat("é", 125)
	if err := p.Validate(); err != nil {
		t.Fatal("valid UTF-8 name rejected", err)
	}
}

func TestEnrollmentProfileResponsesFailClosed(t *testing.T) {
	for _, tc := range []struct{ name, operation, response string }{
		{"definition no ID", "define", `{}`},
		{"definition changed device", "define", `{"profile_uuid":"PROFILE1","devices":{"SYNTHETIC123":"SUCCESS"}}`},
		{"definition duplicate ID", "define", `{"profile_uuid":"PROFILE1","PROFILE_UUID":"PROFILE2"}`},
		{"assignment wrong profile", "assign", `{"profile_uuid":"PROFILE2","devices":{"SYNTHETIC123":"SUCCESS"}}`},
		{"assignment missing device", "assign", `{"profile_uuid":"PROFILE1","devices":{}}`},
		{"assignment extra device", "assign", `{"profile_uuid":"PROFILE1","devices":{"OTHER123":"SUCCESS"}}`},
		{"assignment duplicate device", "assign", `{"profile_uuid":"PROFILE1","devices":{"SYNTHETIC123":"SUCCESS","SYNTHETIC123":"FAILED"}}`},
		{"assignment null status", "assign", `{"profile_uuid":"PROFILE1","devices":{"SYNTHETIC123":null}}`},
		{"assignment unbounded status", "assign", `{"profile_uuid":"PROFILE1","devices":{"SYNTHETIC123":"unexpected raw error"}}`},
		{"throttle no deadline", "assign", `{"profile_uuid":"PROFILE1","devices":{"SYNTHETIC123":"THROTTLED"}}`},
		{"throttle negative deadline", "assign", `{"profile_uuid":"PROFILE1","devices":{"SYNTHETIC123":"THROTTLED"},"retry_after_seconds":-1}`},
		{"throttle fractional deadline", "assign", `{"profile_uuid":"PROFILE1","devices":{"SYNTHETIC123":"THROTTLED"},"retry_after_seconds":1.5}`},
		{"clear profile mismatch", "clear", `{"profile_uuid":"PROFILE1","devices":{"SYNTHETIC123":"SUCCESS"}}`},
		{"details null dictionary", "details", `{"devices":null}`},
		{"details extra device", "details", `{"devices":{"OTHER123":{"response_status":"SUCCESS"}}}`},
		{"details null device", "details", `{"devices":{"SYNTHETIC123":null}}`},
		{"details missing status", "details", `{"devices":{"SYNTHETIC123":{"profile_uuid":"PROFILE1"}}}`},
		{"details mismatched serial", "details", `{"devices":{"SYNTHETIC123":{"response_status":"SUCCESS","serial_number":"OTHER123"}}}`},
		{"details duplicate status", "details", `{"devices":{"SYNTHETIC123":{"response_status":"SUCCESS","Response_Status":"FAILED"}}}`},
		{"profile unknown behavior", "profile", `{"profile_name":"Test","url":"https://mdm.example.test/enroll","new_security_option":true}`},
		{"profile web authentication", "profile", `{"profile_name":"Test","url":"https://mdm.example.test/enroll","configuration_web_url":"https://different.example.test"}`},
		{"profile null removal", "profile", `{"profile_name":"Test","url":"https://mdm.example.test/enroll","is_mdm_removable":null}`},
		{"profile shared device", "profile", `{"profile_name":"Test","url":"https://mdm.example.test/enroll","is_multi_user":true}`},
		{"profile wrong ID", "profile", `{"profile_name":"Test","url":"https://mdm.example.test/enroll","profile_uuid":"OTHER1"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/session" {
					fmt.Fprint(w, `{"auth_session_token":"synthetic-session"}`)
					return
				}
				fmt.Fprint(w, tc.response)
			})
			var err error
			switch tc.operation {
			case "define":
				_, err = c.DefineProfile(t.Context(), testEnrollmentProfile())
			case "profile":
				_, err = c.Profile(t.Context(), "PROFILE1")
			case "assign":
				_, err = c.AssignProfile(t.Context(), "PROFILE1", []string{"SYNTHETIC123"})
			case "clear":
				_, err = c.ClearProfile(t.Context(), []string{"SYNTHETIC123"})
			case "details":
				_, err = c.DeviceDetails(t.Context(), []string{"SYNTHETIC123"})
			}
			if !errors.Is(err, ErrService) {
				t.Fatal("ambiguous enrollment response accepted", err)
			}
		})
	}
}

func TestEnrollmentProfileUnknownOutcomesDefaultsAndThrottle(t *testing.T) {
	var attempts atomic.Int32
	c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/session" {
			fmt.Fprint(w, `{"auth_session_token":"synthetic-session"}`)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "POST /profile":
			attempts.Add(1)
			w.WriteHeader(500)
			fmt.Fprint(w, "sensitive upstream details")
		case "GET /profile":
			fmt.Fprint(w, `{"profile_name":"Test","url":"https://mdm.example.test/enroll","is_multi_user":false,"anchor_certs":[],"configuration_web_url":""}`)
		case "POST /profile/devices":
			fmt.Fprint(w, `{"profile_uuid":"PROFILE1","devices":{"SYNTHETIC123":"THROTTLED","SYNTHETIC124":"SOMETHING_NEW"},"retry_after_seconds":18446744073709551615}`)
		case "POST /devices":
			fmt.Fprint(w, `{"devices":{}}`)
		}
	})
	if _, err := c.DefineProfile(t.Context(), testEnrollmentProfile()); !errors.Is(err, ErrService) || attempts.Load() != 1 {
		t.Fatal("uncertain profile creation was replayed", err)
	}
	p, err := c.Profile(t.Context(), "PROFILE1")
	if err != nil || !p.AllowPairing || !p.Removable || p.Supervised || p.Mandatory {
		t.Fatal("Apple defaults changed", err)
	}
	result, err := c.AssignProfile(t.Context(), "PROFILE1", []string{"SYNTHETIC123", "SYNTHETIC124"})
	if err != nil || result.Devices["SYNTHETIC124"] != "SOMETHING_NEW" || result.RetryAfter < 200*365*24*time.Hour {
		t.Fatal("unknown status or long throttle was converted to success/early retry", err)
	}
	missing, err := c.DeviceDetails(t.Context(), []string{"SYNTHETIC123"})
	if err != nil || len(missing) != 0 {
		t.Fatal("missing device became positive ownership evidence", err)
	}
}
