package handlers

import (
	"context"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
)

// PublishNetbirdPreparation sends one direct download/inspection RPC. Inventory
// admission must commit its complete digest first. It cannot send a native
// installation command, and lost responses never trigger automatic redelivery.
func (h *Handler) PublishNetbirdPreparation(parent context.Context, p netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error) {
	if parent == nil || !p.Executable(p.Identity, time.Now()) {
		return nil, inventory.ErrNetbirdOperationInvalid
	}
	data, err := netbirdcommand.EncodePreparation(p)
	if err != nil {
		return nil, inventory.ErrNetbirdOperationInvalid
	}
	defer clear(data)
	subject, err := netbirdcommand.PreparationSubject(p.DeviceID)
	if err != nil {
		return nil, inventory.ErrNetbirdOperationInvalid
	}
	bounded, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	ctx, finish := context.WithDeadline(bounded, p.ExpiresAt)
	defer finish()
	if ctx.Err() != nil {
		return nil, inventory.ErrNetbirdOperationNotReady
	}
	h.inventoryPublisher.mu.RLock()
	js := h.inventoryPublisher.js
	h.inventoryPublisher.mu.RUnlock()
	if js == nil {
		return nil, inventory.ErrNetbirdOperationNotReady
	}
	response, err := js.Conn().RequestWithContext(ctx, subject, data)
	if err != nil || response == nil || ctx.Err() != nil {
		return nil, inventory.ErrNetbirdOperationNotReady
	}
	result, err := netbirdcommand.DecodePreparationResponse(response.Data, p)
	if err != nil {
		return nil, inventory.ErrNetbirdOperationConflict
	}
	return &result, nil
}
