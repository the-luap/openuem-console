package netbirdapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-uem/nats"
	"github.com/stretchr/testify/require"
)

func TestGroupsOwnedTLSBoundsAndCancellation(t *testing.T) {
	var requests, redirects atomic.Int64
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirects.Add(1); _, _ = io.WriteString(w, "[]") }))
	defer redirect.Close()
	response := `[{"id":"opaque-ID-1","name":"Owned <group-with-hyphens>","peers_count":2}]`
	status := http.StatusOK
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		require.Equal(t, "/management/api/groups", r.URL.Path)
		require.Equal(t, "Token owned-provider-token", r.Header.Get("Authorization"))
		require.Equal(t, "application/json", r.Header.Get("Accept"))
		w.Header().Set("Location", redirect.URL+"/must-not-receive-token")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, response)
	}))
	defer server.Close()
	read := func() ([]nats.NetBirdGroups, error) {
		return Groups(t.Context(), server.Client().Transport, server.URL+"/management/", "owned-provider-token")
	}
	groups, err := read()
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Equal(t, "opaque-ID-1", groups[0].ID)
	require.Equal(t, 2, groups[0].PeersCount)
	for _, bad := range []string{"null", "{}", "[", "[] []", `[{"id":""}]`, `[{"id":"duplicate"},{"id":"duplicate"}]`, `[{"id":"id","peers_count":-1}]`, strings.Repeat("x", (1<<20)+1)} {
		response = bad
		groups, err = read()
		require.ErrorIs(t, err, ErrUnavailable)
		require.Nil(t, groups)
	}
	many := make([]nats.NetBirdGroups, 1001)
	body, err := json.Marshal(many)
	require.NoError(t, err)
	response = string(body)
	_, err = read()
	require.ErrorIs(t, err, ErrUnavailable)
	response = "[]"
	for _, status = range []int{http.StatusFound, http.StatusUnauthorized, http.StatusInternalServerError} {
		_, err = read()
		require.ErrorIs(t, err, ErrUnavailable)
	}
	require.Zero(t, redirects.Load(), "provider redirects must never be followed")
	before := requests.Load()
	for _, base := range []string{strings.Replace(server.URL, "https:", "http:", 1), server.URL + "?query=1", server.URL + "#fragment", server.URL + "?", "https://user:password@invalid.test"} {
		_, err = Groups(t.Context(), server.Client().Transport, base, "owned-provider-token")
		require.ErrorIs(t, err, ErrUnavailable)
	}
	require.Equal(t, before, requests.Load())
	status = http.StatusOK
	groups, err = read()
	require.NoError(t, err)
	require.Empty(t, groups)
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer slow.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err = Groups(ctx, slow.Client().Transport, slow.URL, "owned")
	require.ErrorIs(t, err, ErrUnavailable)
}
