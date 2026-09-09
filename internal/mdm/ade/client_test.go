package ade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixtureClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	c := NewClient(testToken(t))
	c.origin = server.URL
	c.http = server.Client()
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	t.Cleanup(c.Close)
	return c
}

func TestOAuthPublishedSignatureVector(t *testing.T) {
	u, _ := url.Parse("http://photos.example.net/photos?file=vacation.jpg&size=original")
	value := oauthHeader("GET", u, tokenData{ConsumerKey: "dpf43f3p2l4k3l03", ConsumerSecret: "kd94hf93k423kf44", AccessToken: "nnch734d00sl2jdk", AccessSecret: "pfkkdhi9sl3r4s00"}, time.Unix(1191242096, 0), "kllo9940pd9333jh")
	if !strings.Contains(value, `oauth_signature="tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D"`) {
		t.Fatal("OAuth signature differs from the published example")
	}
}

func TestClientSessionRenewalHeaderRotationAndDevicePages(t *testing.T) {
	var sessions, accounts atomic.Int32
	c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" || r.Header.Get("X-Server-Protocol-Version") != "10" {
			t.Error("missing protocol headers")
		}
		switch r.URL.Path {
		case "/session":
			if r.Method != "GET" || !strings.HasPrefix(r.Header.Get("Authorization"), "OAuth ") || r.Header.Get("X-ADM-Auth-Session") != "" {
				t.Error("invalid session authentication")
			}
			fmt.Fprintf(w, `{"auth_session_token":"session-%d"}`, sessions.Add(1))
		case "/account":
			if accounts.Add(1) == 1 {
				w.WriteHeader(401)
				return
			}
			if r.Header.Get("X-ADM-Auth-Session") != "session-2" || r.Header.Get("Authorization") != "" {
				t.Error("stale authentication")
			}
			w.Header().Set("X-ADM-Auth-Session", "rotated-session")
			fmt.Fprint(w, `{"server_uuid":"A0000000-0000-4000-8000-000000000001","server_name":"Synthetic server","org_id":"synthetic-org","org_name":"Example"}`)
		case "/server/devices", "/devices/sync":
			if r.Method != "POST" || r.Header.Get("X-ADM-Auth-Session") != "rotated-session" {
				t.Error("session replacement was ignored")
			}
			var request struct {
				Limit  int
				Cursor string
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.Limit != PageLimit {
				t.Error("unbounded page request")
			}
			if r.URL.Path == "/devices/sync" {
				if request.Cursor != "abc123" {
					t.Error("cursor changed")
				}
				fmt.Fprintf(w, `{"devices":[{"serial_number":"SYNTHETIC123","op_type":"deleted","op_date":%q}],"cursor":"def456","more_to_follow":false}`, time.Now().UTC().Format(time.RFC3339))
			} else {
				fmt.Fprint(w, `{"devices":[{"serial_number":"SYNTHETIC123","device_family":"Mac","profile_status":"empty"}],"cursor":"abc123","more_to_follow":false}`)
			}
		default:
			t.Error("unexpected service path")
			w.WriteHeader(404)
		}
	})
	a, err := c.Account(t.Context())
	if err != nil || a.ServerID != "a0000000-0000-4000-8000-000000000001" || sessions.Load() != 2 {
		t.Fatal("account verification failed", err)
	}
	p, err := c.Devices(t.Context(), "", false)
	if err != nil || len(p.Devices) != 1 || p.More {
		t.Fatal("fetch failed", err)
	}
	p, err = c.Devices(t.Context(), p.Cursor, true)
	if err != nil || p.Devices[0].Operation != "deleted" {
		t.Fatal("delta failed", err)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", c, c), "synthetic-access") {
		t.Fatal("client diagnostics expose secrets")
	}
}

func TestClientBoundsFailuresRedirectsAndCancellation(t *testing.T) {
	for _, mode := range []string{"redirect", "unauthorized", "throttled", "oversized", "duplicate", "invalid-cursor", "missing-more", "cycle", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path == "/session" {
					fmt.Fprint(w, `{"auth_session_token":"synthetic-session"}`)
					return
				}
				switch mode {
				case "redirect":
					w.Header().Set("Location", "https://unrelated.example.test/")
					w.WriteHeader(302)
				case "unauthorized":
					w.WriteHeader(401)
				case "throttled":
					w.Header().Set("Retry-After", "172800")
					w.WriteHeader(429)
				case "oversized":
					fmt.Fprint(w, strings.Repeat(" ", maxResponse+1))
				case "duplicate":
					fmt.Fprint(w, `{"cursor":"first","cursor":"second","more_to_follow":false}`)
				case "invalid-cursor":
					w.WriteHeader(400)
					fmt.Fprint(w, `{"error_code":"EXPIRED_CURSOR"}`)
				case "missing-more":
					fmt.Fprint(w, `{"cursor":"next","devices":[]}`)
				case "cycle":
					fmt.Fprint(w, `{"cursor":"previous","more_to_follow":true,"devices":[]}`)
				}
			})
			ctx := t.Context()
			if mode == "cancelled" {
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
			}
			_, err := c.Devices(ctx, "previous", true)
			if err == nil {
				t.Fatal("unsafe response accepted")
			}
			if mode == "throttled" {
				var retry *RetryError
				if !errors.As(err, &retry) || retry.After != 48*time.Hour {
					t.Fatal("Retry-After shortened", err)
				}
			}
			if mode == "invalid-cursor" && !errors.Is(err, ErrCursor) {
				t.Fatal("expired cursor not distinguished")
			}
			if calls.Load() > 4 {
				t.Fatal("unbounded authentication retry")
			}
			if strings.Contains(err.Error(), "unrelated") || strings.Contains(err.Error(), "synthetic") {
				t.Fatal("service details escaped")
			}
		})
	}
}

func TestClientRejectsIncompletePagesAndRestartsRejectedCursors(t *testing.T) {
	for _, body := range []string{`{"cursor":"next","more_to_follow":false}`, `{"cursor":"next","more_to_follow":false,"devices":null}`} {
		c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/session" {
				fmt.Fprint(w, `{"auth_session_token":"synthetic-session"}`)
				return
			}
			fmt.Fprint(w, body)
		})
		if _, err := c.Devices(t.Context(), "", false); !errors.Is(err, ErrService) {
			t.Fatal("incomplete full page accepted as empty inventory")
		}
	}
	for _, code := range []string{"EXPIRED_CURSOR", "INVALID_CURSOR", "EXHAUSTED_CURSOR", "CURSOR_REQUIRED"} {
		for _, delta := range []bool{true, false} {
			c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/session" {
					fmt.Fprint(w, `{"auth_session_token":"synthetic-session"}`)
					return
				}
				w.WriteHeader(400)
				fmt.Fprint(w, code)
			})
			if _, err := c.Devices(t.Context(), "previous", delta); !errors.Is(err, ErrCursor) {
				t.Fatal("rejected cursor was not classified", code, delta, err)
			}
		}
	}
}
