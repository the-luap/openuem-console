package computers_views

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nats "github.com/open-uem/nats"
	"github.com/open-uem/nats/netbirdstate"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

func TestNetbirdProfileSelectorPreservesIdentities(t *testing.T) {
	for _, kind := range []string{"ordinary", "duplicate", "legacy", "injected", "empty", "malformed"} {
		details := []nats.NetbirdProfile{{ID: "default", Name: "office, with spaces", Active: true}, {ID: "a1b2c3d4", Name: "home"}}
		switch kind {
		case "duplicate":
			details[1].Name = details[0].Name
		case "injected":
			details[0].Name = `<img src=x onerror="window.__netbirdInjected=true">` + strings.TrimSpace(strings.Repeat("long label ", 12))
		}
		stored, err := netbirdstate.Encode(nats.Netbird{ProfileDetails: details})
		require.NoError(t, err)
		switch kind {
		case "legacy":
			stored = "default,home"
		case "empty":
			stored = ""
		case "malformed":
			stored = "openuem-netbird-profiles:v2:[]"
		}
		profiles := netbirdProfileOptions(stored)
		var body bytes.Buffer
		body.WriteString(`<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"></head><body><main class="p-4"><form id="netbird-profile-form" method="post" action="/owned/netbird/switchprofile">`)
		require.NoError(t, NetbirdProfileSelect(profiles).Render(t.Context(), &body))
		body.WriteString(`<button id="submit-profile" type="submit">Switch profile</button></form></main></body></html>`)
		doc, err := html.Parse(bytes.NewReader(body.Bytes()))
		require.NoError(t, err)
		var values, labels []string
		var visit func(*html.Node)
		visit = func(node *html.Node) {
			if node.Type == html.ElementNode && node.Data == "img" {
				t.Fatal("profile name became HTML")
			}
			if node.Type == html.ElementNode && node.Data == "option" {
				for _, attr := range node.Attr {
					if attr.Key == "value" && attr.Val != "" {
						values = append(values, attr.Val)
						if node.FirstChild != nil {
							labels = append(labels, node.FirstChild.Data)
						}
					}
				}
			}
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				visit(child)
			}
		}
		visit(doc)
		require.Len(t, values, len(profiles))
		for i, p := range profiles {
			require.Equal(t, p.Handle(), values[i])
			require.Equal(t, p.Label(), labels[i])
		}
		if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
			require.NoError(t, os.MkdirAll(dir, 0755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "netbird-profiles-"+kind+".html"), body.Bytes(), 0600))
		}
	}
}
