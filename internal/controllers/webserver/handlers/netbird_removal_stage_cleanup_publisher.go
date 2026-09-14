package handlers

import (
	"context"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
)

// PublishNetbirdRemovalStageCleanup accepts only a separate reviewed current scaffold cleanup.
// Its caller must commit the exact independent cleanup delivery attempt before this RPC.
// A lost response requires receipt observation, never automatic redelivery.
func (h *Handler) PublishNetbirdRemovalStageCleanup(parent context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
	if parent == nil || c.Version != netbirdcommand.RemovalStageCleanupVersion || !c.Executable(c.Identity, time.Now()) {
		return nil, inventory.ErrNetbirdOperationInvalid
	}
	data, err := netbirdcommand.Encode(c)
	if err != nil {
		return nil, inventory.ErrNetbirdOperationInvalid
	}
	defer clear(data)
	subject, err := netbirdcommand.Subject(c.DeviceID)
	if err != nil {
		return nil, inventory.ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithDeadline(parent, c.ExpiresAt)
	defer cancel()
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
	receipt, err := netbirdcommand.DecodeReceipt(response.Data)
	if err != nil || !receipt.Matches(c) {
		return nil, inventory.ErrNetbirdOperationConflict
	}
	return &receipt, nil
}
