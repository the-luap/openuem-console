package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nats-io/nats.go"
)

const endpointInboundUnavailable = "Direct file transfer, device logs and remote access are disabled in this deployment."

func (h *Handler) requireEndpointInbound() error {
	if h.IndividualAgentService != nil {
		return echo.NewHTTPError(http.StatusForbidden, endpointInboundUnavailable)
	}
	return nil
}

// Reject legacy service operations synchronously instead of reporting success
// before an asynchronous broker permission denial. Individual command subjects
// must also satisfy the broker's independently enforced console permissions.
func (h *Handler) brokerSubject(subject string) error {
	if h.IndividualAgentService != nil {
		parts := strings.Split(subject, ".")
		if len(parts) < 3 || len(parts) > 5 || parts[0] != "agent" || strings.ContainsAny(subject, "*> \r\n\t") {
			return errors.New("this operation requires a separately configured internal service")
		}
		for _, part := range parts {
			if part == "" {
				return errors.New("invalid individual command subject")
			}
		}
	}
	if h.NATSConnection == nil {
		return nats.ErrConnectionClosed
	}
	return nil
}

func (h *Handler) PublishBroker(subject string, data []byte) error {
	if err := h.brokerSubject(subject); err != nil {
		return err
	}
	return h.NATSConnection.Publish(subject, data)
}

func (h *Handler) RequestBroker(subject string, data []byte, timeout time.Duration) (*nats.Msg, error) {
	if err := h.brokerSubject(subject); err != nil {
		return nil, err
	}
	return h.NATSConnection.Request(subject, data, timeout)
}
