package handlers

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestAppleUpdatePromotionFormBoundary(t *testing.T) {
	states := []string{"valid", "organization-source", "legacy-source", "unknown-source", "100-targets", "101-targets", "empty-targets", "malformed-target", "unconfirmed", "signed-revision", "padded-revision", "zero-revision", "overflow-revision", "signed-group-revision", "missing-csrf", "wrong-csrf", "header-only", "query", "empty-query", "json", "encoding", "duplicate-content-type", "oversized", "chunked-oversized", "parsed-oversized", "malformed", "unknown", "pilot-field"}
	for _, field := range []string{"csrf", "destination_plan", "expected_revision", "group_id", "group_revision", "group_source", "request_key", "devices", "confirmed"} {
		states = append(states, "duplicate-"+field)
	}
	for _, state := range states {
		t.Run(state, func(t *testing.T) {
			f := url.Values{"csrf": {"owned-csrf"}, "destination_plan": {"30000000-0000-4000-8000-000000000002"}, "expected_revision": {"2"}, "group_id": {"20000000-0000-4000-8000-000000000001"}, "group_revision": {"3"}, "group_source": {"site"}, "request_key": {"60000000-0000-4000-8000-000000000001"}, "devices": {"10000000-0000-4000-8000-000000000001:" + strings.Repeat("a", 64)}, "confirmed": {"yes"}}
			switch state {
			case "organization-source":
				f.Set("group_source", "organization")
			case "legacy-source":
				f.Del("group_source")
			case "unknown-source":
				f.Set("group_source", "unknown")
			case "100-targets", "101-targets":
				f.Set("group_source", "organization")
				n := 100
				if state == "101-targets" {
					n = 101
				}
				rows := make([]string, n)
				for i := range rows {
					rows[i] = fmt.Sprintf("10000000-0000-4000-8000-%012d:%s", i, strings.Repeat("a", 64))
				}
				f.Set("devices", strings.Join(rows, "\n"))
			case "empty-targets":
				f.Set("devices", "")
			case "malformed-target":
				f.Set("devices", "missing-separator")
			case "unconfirmed":
				f.Del("confirmed")
			case "signed-revision":
				f.Set("expected_revision", "+2")
			case "padded-revision":
				f.Set("expected_revision", "02")
			case "zero-revision":
				f.Set("expected_revision", "0")
			case "overflow-revision":
				f.Set("expected_revision", "2147483648")
			case "signed-group-revision":
				f.Set("group_revision", "+3")
			case "missing-csrf", "header-only":
				f.Del("csrf")
			case "wrong-csrf":
				f.Set("csrf", "wrong")
			case "unknown":
				f.Set("site_id", "2")
			case "pilot-field":
				f.Set("pilot_assignment", "40000000-0000-4000-8000-000000000002")
			}
			if strings.HasPrefix(state, "duplicate-") {
				field := strings.TrimPrefix(state, "duplicate-")
				f.Add(field, f.Get(field))
			}
			if strings.Contains(state, "oversized") {
				f.Set("devices", strings.Repeat("x", 16385))
			}
			path := "/ios/update-plans/30000000-0000-4000-8000-000000000001/group-assignments/40000000-0000-4000-8000-000000000001/promotions"
			if state == "query" {
				path += "?destination_plan=other"
			}
			if state == "empty-query" {
				path += "?"
			}
			body := f.Encode()
			if state == "malformed" {
				body += "&request_key=%zz"
			}
			if state == "100-targets" {
				require.Greater(t, len(body), 8192)
				require.Less(t, len(body), 16384)
			}
			r := httptest.NewRequest("POST", path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			switch state {
			case "json":
				r.Header.Set("Content-Type", "application/json")
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
			case "duplicate-content-type":
				r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			case "header-only":
				r.Header.Set("X-CSRF-Token", "owned-csrf")
			case "chunked-oversized":
				r.ContentLength = -1
			case "parsed-oversized":
				r.ContentLength = -1
				r.PostForm = f
			}
			c := echo.New().NewContext(r, httptest.NewRecorder())
			c.Set("csrf", "owned-csrf")
			c.SetParamNames("plan", "assignment")
			c.SetParamValues("30000000-0000-4000-8000-000000000001", "40000000-0000-4000-8000-000000000001")
			q, organization, err := appleUpdatePromotionForm(c)
			if state == "valid" || state == "100-targets" || state == "organization-source" || state == "legacy-source" {
				require.NoError(t, err)
				require.Equal(t, state == "organization-source" || state == "100-targets", organization)
				require.Equal(t, c.Param("plan"), q.PilotPlanID)
				require.Equal(t, c.Param("assignment"), q.PilotAssignmentID)
				require.Equal(t, 2, q.DestinationRevision)
				require.Equal(t, 3, q.GroupRevision)
				require.Equal(t, f.Get("destination_plan"), q.DestinationPlanID)
				if state == "100-targets" {
					require.Len(t, q.Targets, 100)
				}
			} else {
				require.Error(t, err)
			}
		})
	}
}
