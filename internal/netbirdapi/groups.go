// Package netbirdapi exposes the shared bounded NetBird group reader.
package netbirdapi

import (
	"context"
	"github.com/open-uem/nats"
	shared "github.com/open-uem/nats/netbirdapi"
	"net/http"
)

var ErrUnavailable = shared.ErrUnavailable

func Groups(ctx context.Context, transport http.RoundTripper, base, token string) ([]nats.NetBirdGroups, error) {
	return shared.Groups(ctx, transport, base, token)
}
