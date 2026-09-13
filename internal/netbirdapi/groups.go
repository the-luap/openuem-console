// Package netbirdapi provides bounded, read-only NetBird group lookups.
package netbirdapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/open-uem/nats"
)

var ErrUnavailable = errors.New("NetBird groups are unavailable")

// Groups only contacts the configured HTTPS origin. Redirects and response
// bodies are never forwarded to the caller, including provider error bodies.
func Groups(ctx context.Context, transport http.RoundTripper, base, token string) ([]nats.NetBirdGroups, error) {
	u, err := url.Parse(base)
	if err != nil || len(base) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || token == "" || len(token) > 16384 || strings.ContainsAny(token, "\r\n\x00") {
		return nil, ErrUnavailable
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/groups"
	u.RawPath = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Token "+token)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrUnavailable
	}
	const maximum = 1 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || len(body) > maximum {
		return nil, ErrUnavailable
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '[' {
		return nil, ErrUnavailable
	}
	groups := []nats.NetBirdGroups{}
	if json.Unmarshal(body, &groups) != nil || len(groups) > 1000 {
		return nil, ErrUnavailable
	}
	seen := map[string]bool{}
	for _, group := range groups {
		if group.ID == "" || len(group.ID) > 128 || !utf8.ValidString(group.ID) || strings.ContainsRune(group.ID, 0) || seen[group.ID] || len(group.Name) > 1024 || !utf8.ValidString(group.Name) || strings.ContainsRune(group.Name, 0) || group.PeersCount < 0 {
			return nil, ErrUnavailable
		}
		seen[group.ID] = true
	}
	return groups, nil
}
