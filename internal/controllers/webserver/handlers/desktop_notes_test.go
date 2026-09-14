package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/stretchr/testify/require"
)

func exerciseDesktopNotesRoutes(t *testing.T, h *Handler, ctx context.Context, tenant, site, sibling, foreign int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	old, err := h.Model.Client.Agent.Get(ctx, "windows-fixture")
	require.NoError(t, err)
	defer h.Model.Client.Agent.UpdateOneID(old.ID).SetNotes(old.Notes).Exec(ctx)
	base := fmt.Sprintf("/tenant/%d/site/%d/computers/windows-fixture/notes", tenant, site)
	revision := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		match := regexp.MustCompile(`name="revision" value="([a-f0-9-]+)"`).FindStringSubmatch(w.Body.String())
		require.Len(t, match, 2)
		return match[1]
	}
	for _, actor := range []string{"organization-admin", "apple-console-admin"} {
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), fmt.Sprintf("/tenant/%d/site/%d", tenant, site)} {
			path := prefix + "/computers/windows-fixture/notes"
			w := request(actor, "GET", path, nil)
			require.Equal(t, 200, w.Code)
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			form := url.Values{"revision": {revision(w)}, "markdown": {"Private notes for " + actor}}
			w = request(actor, "POST", path, form)
			require.Equal(t, 303, w.Code)
			w = request(actor, "GET", w.Header().Get("Location"), nil)
			require.Equal(t, 200, w.Code)
			require.Contains(t, w.Body.String(), "Private notes for "+actor)
		}
	}
	for _, actor := range []string{"scoped-viewer", "scoped-operator"} {
		for _, prefix := range []string{"", fmt.Sprintf("/tenant/%d", tenant), fmt.Sprintf("/tenant/%d/site/%d", tenant, site)} {
			path := prefix + "/computers/windows-fixture/notes"
			for _, method := range []string{"GET", "POST"} {
				w := request(actor, method, path, url.Values{"markdown": {"Denied"}})
				require.Equal(t, 403, w.Code)
				require.NotContains(t, w.Body.String(), "Private notes for")
			}
			w := request(actor, "GET", prefix+"/computers/windows-fixture/inventory", nil)
			require.NotContains(t, w.Body.String(), "/computers/windows-fixture/notes")
		}
	}
	for _, target := range []string{"inventory-foreign", "inventory-ambiguous", "inventory-two-local-sites", "inventory-orphan", "inventory-waiting", "missing"} {
		for _, method := range []string{"GET", "POST"} {
			w := request("organization-admin", method, strings.Replace(base, "windows-fixture", target, 1), url.Values{"revision": {revision(request("organization-admin", "GET", base, nil))}, "markdown": {"Hidden"}})
			require.Equal(t, 404, w.Code, target)
		}
	}
	for _, path := range []string{fmt.Sprintf("/tenant/%d/site/%d/computers/windows-fixture/notes", tenant, sibling), fmt.Sprintf("/tenant/%d/computers/windows-fixture/notes", foreign)} {
		w := request("organization-admin", "GET", path, nil)
		require.Equal(t, 404, w.Code)
	}
	current := revision(request("organization-admin", "GET", base, nil))
	for _, test := range []string{"csrf", "missing", "duplicate", "unknown", "query", "oversized", "body-limit", "control"} {
		form := url.Values{"revision": {current}, "markdown": {"Rejected"}}
		path, want := base, 400
		switch test {
		case "csrf":
			form.Set("csrf", "wrong")
			want = 403
		case "missing":
			form.Del("revision")
		case "duplicate":
			form.Add("markdown", "Another")
		case "unknown":
			form.Set("tenant", "999")
		case "query":
			path += "?markdown=injected"
		case "oversized":
			form.Set("markdown", strings.Repeat("a", inventory.MaxDeviceNotesBytes+1))
		case "body-limit":
			form.Set("markdown", strings.Repeat("a", 210<<10))
			want = 413
		case "control":
			form.Set("markdown", "bad\x00")
		}
		w := request("organization-admin", "POST", path, form)
		require.Equal(t, want, w.Code, test)
	}
	require.NoError(t, h.Model.Client.Agent.UpdateOneID("windows-fixture").SetNotes("**Concurrent saved note**").Exec(ctx))
	draft := "My preserved draft </textarea><script>window.notesOwned=true</script>"
	w := request("organization-admin", "POST", base, url.Values{"revision": {current}, "markdown": {draft}})
	require.Equal(t, 409, w.Code)
	require.Contains(t, w.Body.String(), "Your draft is preserved")
	require.Contains(t, w.Body.String(), "My preserved draft &lt;/textarea&gt;&lt;script&gt;")
	require.NotContains(t, w.Body.String(), "<script>window.notesOwned")
	require.Contains(t, w.Body.String(), "<strong>Concurrent saved note</strong>")
	merged := "Merged saved note and draft"
	w = request("organization-admin", "POST", base, url.Values{"revision": {revision(w)}, "markdown": {merged}})
	require.Equal(t, 303, w.Code)
	current = revision(request("organization-admin", "GET", base, nil))
	_, err = h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit ADD CONSTRAINT route_notes_failure CHECK(action NOT IN ('inventory.notes.read','inventory.notes.update')) NOT VALID`)
	require.NoError(t, err)
	defer h.Model.DB.ExecContext(ctx, `ALTER TABLE uem_inventory_audit DROP CONSTRAINT route_notes_failure`)
	for _, method := range []string{"GET", "POST"} {
		w := request("organization-admin", method, base, url.Values{"revision": {current}, "markdown": {"Audit must roll back"}})
		require.Equal(t, 503, w.Code)
		require.NotContains(t, w.Body.String(), merged)
		require.NotContains(t, w.Body.String(), "route_notes_failure")
	}
	stored, err := h.Model.Client.Agent.Get(ctx, "windows-fixture")
	require.NoError(t, err)
	require.Equal(t, merged, stored.Notes)
}
