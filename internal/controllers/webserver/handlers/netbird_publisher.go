package handlers

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
)

// PublishNetbirdOperation sends once on the versioned direct subject. The
// operation store must commit the exact command digest before entering here.
func (h *Handler) PublishNetbirdOperation(parent context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
	if parent == nil || !c.Executable(c.Identity, time.Now()) {
		return nil, inventory.ErrNetbirdOperationInvalid
	}
	data, err := netbirdcommand.Encode(c)
	if err != nil {
		return nil, err
	}
	subject, err := netbirdcommand.Subject(c.DeviceID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(parent, c.ExpiresAt)
	defer cancel()
	h.inventoryPublisher.mu.RLock()
	js := h.inventoryPublisher.js
	h.inventoryPublisher.mu.RUnlock()
	if js == nil {
		return nil, inventory.ErrNetbirdOperationNotReady
	}
	response, err := js.Conn().RequestWithContext(ctx, subject, data)
	if err != nil {
		return nil, err
	}
	if response == nil || ctx.Err() != nil {
		return nil, inventory.ErrNetbirdOperationNotReady
	}
	receipt, err := netbirdcommand.DecodeReceipt(response.Data)
	if err != nil || !receipt.Matches(c) || receipt.Status != "completed" {
		return nil, inventory.ErrNetbirdOperationConflict
	}
	return &inventory.NetbirdOperationResult{RequestID: receipt.RequestID, DeviceID: receipt.DeviceID, Revision: receipt.Revision, CommandHash: receipt.CommandHash, Operation: receipt.Operation, Success: true}, nil
}

// RequestNetbirdControl never retries a mutating control. Callers own its immutable
// resolution identity and must persist it before publishing. A fresh read-only
// receipt query can recover a lost control reply without changing that identity.
func (h *Handler) RequestNetbirdControl(parent context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
	if parent == nil || !c.Executable(c.Identity, time.Now()) {
		return nil, inventory.ErrNetbirdOperationInvalid
	}
	data, err := netbirdcommand.EncodeControl(c)
	if err != nil {
		return nil, err
	}
	subject, err := netbirdcommand.ControlSubject(c.DeviceID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(parent, c.ExpiresAt)
	defer cancel()
	h.inventoryPublisher.mu.RLock()
	js := h.inventoryPublisher.js
	h.inventoryPublisher.mu.RUnlock()
	if js == nil {
		return nil, inventory.ErrNetbirdOperationNotReady
	}
	response, err := js.Conn().RequestWithContext(ctx, subject, data)
	if err != nil {
		return nil, err
	}
	if response == nil || ctx.Err() != nil {
		return nil, inventory.ErrNetbirdOperationNotReady
	}
	r, err := netbirdcommand.DecodeControlResponse(response.Data, c)
	if err != nil {
		return nil, inventory.ErrNetbirdOperationConflict
	}
	return &r, nil
}

func (h *Handler) InspectNetbirdJournal(parent context.Context, identity netbirdcommand.Identity) (netbirdcommand.State, error) {
	if parent == nil || !identity.Valid() {
		return netbirdcommand.State{}, inventory.ErrNetbirdOperationInvalid
	}
	now := time.Now().UTC()
	expires := now.Add(netbirdcommand.ControlLifetime)
	if deadline, ok := parent.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	c := netbirdcommand.ControlRequest{Version: netbirdcommand.Version, Identity: identity, RequestID: uuid.NewString(), Kind: "state", IssuedAt: now, ExpiresAt: expires}
	r, err := h.RequestNetbirdControl(parent, c)
	if err != nil {
		return netbirdcommand.State{}, err
	}
	if r.Outcome != "ok" {
		return netbirdcommand.State{}, inventory.ErrNetbirdOperationNotReady
	}
	return r.State, nil
}
