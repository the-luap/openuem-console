package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestDesktopTagFormRetainsHTMXProtocolAndRejectsAmbiguousIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, method, query, body string
		change, invalid           bool
	}{
		{"add", "POST", "", "agentId=legacy_1&tagId=42&page=2&filterByOs=windows", true, false},
		{"remove", "DELETE", "?agentId=legacy_1&tagId=42&page=2", "", true, false},
		{"filter", "POST", "", "page=2&filterByTag42=on", false, false},
		{"read", "GET", "?agentId=legacy_1&tagId=42", "", false, false},
		{"post query", "POST", "?agentId=legacy_1&tagId=42", "", false, true},
		{"duplicate tag", "POST", "", "agentId=legacy_1&tagId=42&tagId=43", false, true},
		{"duplicate device", "DELETE", "?agentId=legacy_1&agentId=other&tagId=42", "", false, true},
		{"mixed post", "POST", "?tagId=42", "agentId=legacy_1&tagId=42", false, true},
		{"delete body", "DELETE", "?agentId=legacy_1&tagId=42", "tagId=42", false, true},
		{"missing device", "POST", "", "tagId=42", false, true},
		{"missing tag", "DELETE", "?agentId=legacy_1", "", false, true},
		{"padded tag", "POST", "", "agentId=legacy_1&tagId=042", false, true},
		{"invalid device", "POST", "", "agentId=legacy/1&tagId=42", false, true},
		{"query syntax", "DELETE", "?agentId=legacy_1&tagId=42&bad=%zz", "", false, true},
		{"body syntax", "POST", "", "agentId=legacy_1&tagId=42&bad=%zz", false, true},
		{"oversized body", "POST", "", "agentId=legacy_1&tagId=42" + strings.Repeat("&", 64<<10), false, true},
		{"oversized query", "DELETE", "?agentId=legacy_1&tagId=42" + strings.Repeat("&", 64<<10), "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/tenant/1/site/2/agents"+tc.query, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			device, id, change, err := tagMembershipForm(echo.New().NewContext(r, httptest.NewRecorder()))
			require.Equal(t, tc.invalid, err != nil)
			require.Equal(t, tc.change, change)
			if change {
				require.Equal(t, "legacy_1", device)
				require.EqualValues(t, 42, id)
			}
		})
	}
}
