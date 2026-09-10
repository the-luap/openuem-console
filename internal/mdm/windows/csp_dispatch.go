package windows

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/open-uem/openuem-console/internal/security/access"
)

type cspStoredResult struct {
	Version    int
	Reason     string
	Resolution string
	Exchange   *cspSessionCommand
}

func (cspStoredResult) String() string     { return "[protected Windows CSP outcome]" }
func (v cspStoredResult) GoString() string { return v.String() }

func (s *Store) openCSPResult(c *cspStoredCommand) (*cspStoredResult, error) {
	if c.result == nil {
		if c.DeliveredSessionID != "" {
			return nil, ErrAuthoritySecret
		}
		return &cspStoredResult{Version: 1}, nil
	}
	plain, err := s.secrets.openBounded(c.result, cspResultPurpose(c), maxCSPProtectedBytes)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var result cspStoredResult
	if decodeSyncMLProtectedJSON(plain, &result) != nil || result.Version != 1 || len(result.Reason) > 128 || len(result.Resolution) > 512 || result.Exchange.validate() != nil || c.DeliveredSessionID != "" && result.Exchange == nil {
		return nil, ErrAuthoritySecret
	}
	if result.Exchange != nil && (result.Exchange.CommandID != c.ID || result.Exchange.MessageID != strconv.Itoa(c.DeliveredMessage)) {
		return nil, ErrAuthoritySecret
	}
	return &result, nil
}

func (s *Store) writeCSPResult(ctx context.Context, tx *sql.Tx, c *cspStoredCommand, result cspStoredResult) error {
	if result.Version != 1 || result.Exchange.validate() != nil {
		return ErrAuthoritySecret
	}
	plain, err := json.Marshal(result)
	if err != nil {
		return ErrAuthoritySecret
	}
	defer clear(plain)
	c.result, err = s.secrets.sealBounded(plain, cspResultPurpose(c), maxCSPProtectedBytes)
	if err != nil {
		return err
	}
	return s.updateCSPMetadata(ctx, tx, c, c.result)
}

func (s *Store) authorizeCSPCreator(ctx context.Context, tx *sql.Tx, c *cspStoredCommand) error {
	capability := access.ManageWindowsCSP
	if c.UpdateRunID != "" {
		if _, _, err := s.updateRunForCommand(ctx, tx, c); err != nil {
			return err
		}
		capability = access.ManageUpdates
	}
	if err := s.permissions.AuthorizeTransaction(ctx, tx, c.CreatedBy, capability, c.Scope); err != nil {
		return err
	}
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM uem_access_revisions WHERE user_id=$1`, c.CreatedBy).Scan(&revision); err != nil {
		return err
	}
	if revision != c.CreatedByRevision {
		return access.ErrDenied
	}
	return nil
}

// Even exact packet replay is a possible delivery. Never send an administrative
// payload after its creator lost authority, its deadline passed, or its outcome
// was already recorded. Pure authentication/probe packets remain replayable.
func (s *Store) authorizeCSPReplay(ctx context.Context, tx *sql.Tx, identity ManagementDeviceIdentity, sessionID string, messageID int) (*cspStoredCommand, error) {
	c, err := scanCSPCommand(tx.QueryRowContext(ctx, `SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND delivered_session_id=$4 AND delivered_message=$5 FOR SHARE`, identity.DeviceID, identity.TenantID, identity.SiteID, sessionID, messageID))
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if c.Phase != "sent" {
		return nil, ErrCSPAlreadySent
	}
	if err := s.authorizeCSPCreator(ctx, tx, c); err != nil {
		return nil, err
	}
	plain, _, err := s.openCSPRequest(c)
	clear(plain)
	if err != nil {
		return nil, err
	}
	if _, err := s.openCSPResult(c); err != nil {
		return nil, err
	}
	if err := checkCSPDeadline(ctx, tx, c); err != nil {
		return nil, err
	}
	if reason, err := s.updateCommandEligibility(ctx, tx, c); err != nil {
		return nil, err
	} else if reason != "" {
		return nil, ErrCSPAlreadySent
	}
	return c, nil
}

func (s *Store) lockCurrentCSP(ctx context.Context, tx *sql.Tx, identity ManagementDeviceIdentity, session *syncMLSession) (*cspStoredCommand, error) {
	if session == nil || session.State.CSP == nil {
		return nil, nil
	}
	state := session.State.CSP
	c, err := scanCSPCommand(tx.QueryRowContext(ctx, `SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR UPDATE`, state.CommandID, identity.DeviceID, identity.TenantID, identity.SiteID))
	if err != nil {
		return nil, err
	}
	if !slices.Contains([]string{"sent", "unknown", "acknowledged", "failed", "abandoned"}, c.Phase) || c.DeliveredSessionID != session.ID || strconv.Itoa(c.DeliveredMessage) != state.MessageID {
		return nil, ErrAuthoritySecret
	}
	payload, command, err := s.openCSPRequest(c)
	clear(payload)
	if err != nil {
		return nil, err
	}
	if c.UpdateRunID != "" {
		if _, _, err := s.updateRunForCommand(ctx, tx, c); err != nil {
			return nil, err
		}
	}
	previous, err := s.openCSPResult(c)
	if err != nil {
		return nil, err
	}
	left, _ := json.Marshal(previous.Exchange)
	right, _ := json.Marshal(state)
	defer clear(left)
	defer clear(right)
	if !bytes.Equal(left, right) {
		return nil, ErrAuthoritySecret
	}
	if err := bindCSPDispatch(session, command, state); err != nil {
		return nil, err
	}
	return c, nil
}

func bindCSPDispatch(session *syncMLSession, command SyncMLCommand, state *cspSessionCommand) error {
	if state.validate() != nil {
		return ErrAuthoritySecret
	}
	shape := newCSPSessionCommand(state.CommandID, state.MessageID, command)
	if len(shape.Operations) != len(state.Operations) {
		return ErrAuthoritySecret
	}
	prefix := session.ID + "-" + state.MessageID + "-"
	first, err := strconv.Atoi(strings.TrimPrefix(state.Operations[0].WireID, prefix))
	if err != nil || first < 1 || first+len(state.Operations) > MaxSyncMLCommands+1 {
		return ErrAuthoritySecret
	}
	parents := map[string]string{}
	for n, operation := range shape.Operations {
		wire := syncMLResponseCommandID(session, state.MessageID, first+n-1)
		got := state.Operations[n]
		if got.WireID != wire || got.Kind != operation.Kind || got.URI != operation.URI || got.ParentID != parents[operation.ParentID] {
			return ErrAuthoritySecret
		}
		parents[operation.WireID] = wire
	}
	return nil
}

func (s *Store) observeCSP(ctx context.Context, tx *sql.Tx, identity ManagementDeviceIdentity, session *syncMLSession, c *cspStoredCommand, requestMessageID string, requestDigest []byte) error {
	if c == nil {
		return nil
	}
	state := session.State.CSP
	previous, err := s.openCSPResult(c)
	if err != nil {
		return err
	}
	// A command can finish before the device ends its SyncML package. Keep
	// accepting protocol housekeeping without rewriting immutable outcomes.
	if c.Phase == "acknowledged" || c.Phase == "failed" || c.Phase == "abandoned" {
		before, _ := json.Marshal(previous.Exchange.Operations)
		after, _ := json.Marshal(state.Operations)
		defer clear(before)
		defer clear(after)
		if !bytes.Equal(before, after) {
			return ErrCSPAlreadySent
		}
		*state = *previous.Exchange
		return nil
	}
	observed := requestMessageID != "" && state.ObservedMessageID == requestMessageID && previous.Exchange.ObservedMessageID != requestMessageID
	outcome := cspOutcome(state)
	if outcome == "" && syncMLTerminal(session.Phase) {
		state.StopReason = "session_" + session.Phase
		outcome = "unknown"
	}
	if !observed && outcome == "" {
		return nil
	}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&c.UpdatedAt); err != nil {
		return err
	}
	c.Revision++
	reason := ""
	if outcome != "" {
		c.Phase = outcome
		if outcome == "unknown" {
			reason = state.StopReason
			if reason == "" {
				reason = "asynchronous_pending"
				for _, operation := range state.Operations {
					if operation.Status == 516 {
						reason = "rollback_failed"
					}
				}
			}
		}
		if outcome == "acknowledged" || outcome == "failed" {
			c.CompletedAt = &c.UpdatedAt
		}
	}
	if err := s.writeCSPResult(ctx, tx, c, cspStoredResult{Version: 1, Reason: reason, Exchange: state}); err != nil {
		return err
	}
	if observed {
		plain, err := json.Marshal(state)
		if err != nil {
			return ErrAuthoritySecret
		}
		defer clear(plain)
		purpose := cspObservationPurpose(c, session.ID, requestMessageID, requestDigest, c.UpdatedAt)
		encrypted, err := s.secrets.sealBounded(plain, purpose, maxCSPProtectedBytes)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO mdm_windows_csp_observations(command_id,device_id,tenant_id,site_id,session_id,message_id,request_digest,encrypted_observation,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, c.ID, identity.DeviceID, identity.TenantID, identity.SiteID, session.ID, requestMessageID, requestDigest, encrypted, c.UpdatedAt)
		if err != nil {
			return err
		}
		if err := auditCSP(ctx, tx, c, "windows-device", "command.observed"); err != nil {
			return err
		}
	}
	if outcome != "" {
		return auditCSP(ctx, tx, c, "windows-device", "command."+outcome)
	}
	return nil
}

func (s *Store) stopCSPSession(ctx context.Context, tx *sql.Tx, identity ManagementDeviceIdentity, session *syncMLSession) error {
	if session.State.CSP == nil {
		return nil
	}
	c, err := s.lockCurrentCSP(ctx, tx, identity, session)
	if err != nil {
		return err
	}
	return s.observeCSP(ctx, tx, identity, session, c, "", nil)
}

func (s *Store) blockCSP(ctx context.Context, tx *sql.Tx, c *cspStoredCommand, reason string) error {
	old, err := s.openCSPResult(c)
	if err != nil {
		return err
	}
	if c.Phase == "blocked" && old.Reason == reason {
		return nil
	}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&c.UpdatedAt); err != nil {
		return err
	}
	c.Revision++
	c.Phase = "blocked"
	if err := s.writeCSPResult(ctx, tx, c, cspStoredResult{Version: 1, Reason: reason}); err != nil {
		return err
	}
	return auditCSP(ctx, tx, c, "windows-device", "command.blocked")
}

func (s *Store) dispatchCSP(ctx context.Context, tx *sql.Tx, identity ManagementDeviceIdentity, session *syncMLSession, response *SyncMLMessage) (*cspStoredCommand, error) {
	state := &session.State
	if session.Phase != "completed" || !state.ClientAuthenticated || !state.ServerVerified || state.Probe == nil || state.Probe.Status != "200" || !state.Probe.HasResult || state.Probe.MoreData || session.LastMessage >= maxSyncMLSessionMessages {
		return nil, nil
	}
	var unresolved bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_windows_csp_commands WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND phase IN ('sent','unknown'))`, identity.DeviceID, identity.TenantID, identity.SiteID).Scan(&unresolved); err != nil {
		return nil, err
	}
	if unresolved {
		return nil, nil
	}
	for n := 0; n < 32; n++ {
		c, err := scanCSPCommand(tx.QueryRowContext(ctx, `SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND phase IN ('queued','blocked') ORDER BY created_at,COALESCE(update_step,0),id LIMIT 1 FOR UPDATE`, identity.DeviceID, identity.TenantID, identity.SiteID))
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		plain, command, err := s.openCSPRequest(c)
		clear(plain)
		if err != nil {
			return nil, err
		}
		if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&c.UpdatedAt); err != nil {
			return nil, err
		}
		cause := ""
		if !c.ExpiresAt.After(c.UpdatedAt) {
			cause = "expired"
		} else if err := s.authorizeCSPCreator(ctx, tx, c); errors.Is(err, access.ErrDenied) {
			cause = "authority_lost"
		} else if err != nil {
			return nil, err
		}
		if cause != "" {
			c.Revision++
			c.Phase = "expired"
			if cause == "authority_lost" {
				c.Phase = "canceled"
			}
			c.CompletedAt = &c.UpdatedAt
			if err := s.writeCSPResult(ctx, tx, c, cspStoredResult{Version: 1, Reason: cause}); err != nil {
				return nil, err
			}
			if err := auditCSP(ctx, tx, c, "windows-device", "command."+cause); err != nil {
				return nil, err
			}
			continue
		}
		if reason, err := s.updateCommandEligibility(ctx, tx, c); err != nil {
			return nil, err
		} else if reason != "" {
			c.Revision++
			c.Phase = "canceled"
			c.CompletedAt = &c.UpdatedAt
			if err := s.writeCSPResult(ctx, tx, c, cspStoredResult{Version: 1, Reason: reason}); err != nil {
				return nil, err
			}
			if err := auditCSP(ctx, tx, c, "windows-device", "command.canceled"); err != nil {
				return nil, err
			}
			continue
		}
		if c.UserTarget && (identity.EnrollmentType != "Full" || state.LoginStatus != "user") {
			return nil, s.blockCSP(ctx, tx, c, "user_context")
		}
		if state.MaximumResponseObjectBytes != 0 && uint64(cspLargestObject(command)) > state.MaximumResponseObjectBytes {
			return nil, s.blockCSP(ctx, tx, c, "object_size")
		}
		candidate := *response
		candidate.Commands = slices.Clone(response.Commands)
		candidate.Commands = append(candidate.Commands, command)
		sent := assignSyncMLResponseIDs(session, &candidate)
		encoded, err := EncodeSyncML(&candidate)
		defer clear(encoded)
		if err != nil || uint64(len(encoded)) > state.MaximumResponseBytes {
			return nil, s.blockCSP(ctx, tx, c, "message_size")
		}
		state.CSP = newCSPSessionCommand(c.ID, response.Header.MessageID, candidate.Commands[len(candidate.Commands)-1])
		state.LastResponse = sent
		session.Phase = "active"
		*response = candidate
		c.Revision++
		c.Phase = "sent"
		c.DeliveredSessionID = session.ID
		c.DeliveredMessage = session.LastMessage
		c.DeliveredAt = &c.UpdatedAt
		if err := s.writeCSPResult(ctx, tx, c, cspStoredResult{Version: 1, Exchange: state.CSP}); err != nil {
			return nil, err
		}
		if err := auditCSP(ctx, tx, c, "windows-device", "command.sent"); err != nil {
			return nil, err
		}
		return c, nil
	}
	return nil, nil
}

func cspLargestObject(command SyncMLCommand) int {
	largest := 0
	for _, item := range command.Items {
		if item.Data != nil {
			operation := cspOperationResult{Text: item.Data.Text, XML: item.Data.XML}
			if item.Meta != nil {
				operation.Format = item.Meta.Format
			}
			largest = max(largest, cspResultLength(operation))
		}
	}
	for _, child := range command.Commands {
		largest = max(largest, cspLargestObject(child))
	}
	return largest
}
