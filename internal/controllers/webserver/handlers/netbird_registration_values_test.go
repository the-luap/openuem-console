package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestNetbirdRegistrationValuesRejectAmbiguousAndOversizedInput(t *testing.T) {
	for _, entry := range []struct{ method, query, body, media, encoding string }{
		{"GET", "group=a&group=a", "", "", ""},
		{"GET", "group=../escape", "", "", ""},
		{"GET", "Group=a", "", "", ""},
		{"GET", "extra_dns=yes&extra_dns=no", "", "", ""},
		{"GET", "group=" + strings.Repeat("g", 129), "", "", ""},
		{"GET", strings.Repeat("a", 24<<10+1), "", "", ""},
		{"GET", "", "unexpected-body", "", ""},
		{"GET", "", "", "", "gzip"},
		{"POST", "", "confirmed=yes&group=a", "application/json", ""},
		{"POST", "group=b", "confirmed=yes&group=a", "application/x-www-form-urlencoded", ""},
		{"POST", "", "confirmed=yes&confirmed=no", "application/x-www-form-urlencoded", ""},
		{"POST", "", "confirmed=yes&request_id=one&request_id=two", "application/x-www-form-urlencoded", ""},
		{"POST", "", "confirmed=yes&setup_key=secret", "application/x-www-form-urlencoded", ""},
		{"POST", "", strings.Repeat("a", 32<<10+1), "application/x-www-form-urlencoded", ""},
		{"POST", "", "confirmed=yes&extra_dns=maybe", "application/x-www-form-urlencoded", ""},
		{"POST", "", "group=a", "application/x-www-form-urlencoded", ""},
	} {
		r := httptest.NewRequest(entry.method, "/registrations?"+entry.query, strings.NewReader(entry.body))
		r.Header.Set("Content-Type", entry.media)
		r.Header.Set("Content-Encoding", entry.encoding)
		_, err := netbirdRegistrationValues(echo.New().NewContext(r, httptest.NewRecorder()), "group", "extra_dns", "request_id", "revision")
		require.Error(t, err)
	}
	values := url.Values{"confirmed": {"yes"}, "extra_dns": {"no"}}
	for i := 0; i < 100; i++ {
		values.Add("group", "owned-"+strings.Repeat("g", i+1))
	}
	parse := func(v url.Values) error {
		r := httptest.NewRequest("POST", "/registrations", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_, err := netbirdRegistrationValues(echo.New().NewContext(r, httptest.NewRecorder()), "group", "extra_dns")
		return err
	}
	require.NoError(t, parse(values))
	values.Add("group", "one-too-many")
	require.Error(t, parse(values))
}
