package handlers

import (
	"context"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/taskexecution"
)

// PublishManualExecution is a single direct request. JetStream redelivery is
// unsafe for commands that change a device. The durable store owns admission,
// the sole attempt record and all decisions after uncertain delivery.
func (h *Handler) PublishManualExecution(ctx context.Context, deviceID, requestID string, payload *taskexecution.Payload) error {
	id, err := uuid.Parse(requestID)
	if !inventory.ValidReportDeviceID(deviceID) || err != nil || id == uuid.Nil || id.String() != requestID || payload == nil || len(payload.Data) == 0 || len(payload.Data) > taskexecution.MaxPayloadSize {
		return inventory.ErrManualInvalid
	}
	switch payload.Operation {
	case "ansible", "windowstask", "runprofile":
	default:
		return inventory.ErrManualUnsupported
	}
	h.inventoryPublisher.mu.RLock()
	js := h.inventoryPublisher.js
	h.inventoryPublisher.mu.RUnlock()
	if js == nil {
		return inventory.ErrRefreshNotReady
	}
	response, err := js.Conn().RequestWithContext(ctx, "agent."+payload.Operation+"."+deviceID, payload.Data)
	if err != nil {
		return err
	}
	if response == nil || len(response.Data) != 0 {
		return inventory.ErrManualRejected
	}
	return nil
}
