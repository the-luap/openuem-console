package windows

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

// CSPObservation is an immutable cumulative snapshot after one authenticated
// device packet. Outcome describes this snapshot, never the command's later state.
type CSPObservation struct {
	SessionID  string                `json:"-" xml:"-" yaml:"-"`
	MessageID  int                   `json:"-" xml:"-" yaml:"-"`
	ReceivedAt time.Time             `json:"-" xml:"-" yaml:"-"`
	Outcome    string                `json:"-" xml:"-" yaml:"-"`
	StopReason string                `json:"-" xml:"-" yaml:"-"`
	Outcomes   []CSPOperationOutcome `json:"-" xml:"-" yaml:"-"`
}

type CSPObservationHistory struct {
	Command      CSPCommand       `json:"-" xml:"-" yaml:"-"`
	Observations []CSPObservation `json:"-" xml:"-" yaml:"-"`
}

func (CSPObservation) String() string            { return "[protected Windows CSP observation]" }
func (v CSPObservation) GoString() string        { return v.String() }
func (CSPObservationHistory) String() string     { return "[protected Windows CSP observation history]" }
func (v CSPObservationHistory) GoString() string { return v.String() }

func cspObservationPurpose(c *cspStoredCommand, sessionID, messageID string, digest []byte, receivedAt time.Time) string {
	return cspPurpose("observation", c) + fmt.Sprintf("/%s/%s/%x/%s", sessionID, messageID, digest, receivedAt.UTC().Format(time.RFC3339Nano))
}

func cspOperationOutcomes(state *cspSessionCommand) []CSPOperationOutcome {
	outcomes := []CSPOperationOutcome{}
	if state != nil {
		for _, operation := range state.Operations {
			outcome := CSPOperationOutcome{CommandID: operation.WireID, ParentID: operation.ParentID, Kind: operation.Kind, URI: operation.URI, Status: operation.Status, OriginalError: operation.OriginalError, Incomplete: operation.MoreData, Format: operation.Format, MIME: operation.MIME}
			if operation.HasResult && !operation.MoreData {
				outcome.Data = &SyncMLData{Text: operation.Text, XML: operation.XML}
			}
			outcomes = append(outcomes, outcome)
		}
	}
	return outcomes
}

// CSPObservations authenticates every listed snapshot but omits its operation
// values. Small pages bound decryption work even for maximum-size Get results.
func (s *Store) CSPObservations(ctx context.Context, actor string, scope access.Scope, deviceID, commandID string, offset, limit int) (*CSPObservationHistory, error) {
	if offset < 0 || offset > maxSyncMLSessionMessages || limit < 1 || limit > 11 {
		return nil, ErrCSPCommand
	}
	return s.readCSPObservations(ctx, actor, scope, deviceID, commandID, 0, offset, limit)
}

// CSPObservationDetails returns exactly one authenticated snapshot, including
// complete values only. Device content must be escaped by the caller's view.
func (s *Store) CSPObservationDetails(ctx context.Context, actor string, scope access.Scope, deviceID, commandID string, messageID int) (*CSPObservationHistory, error) {
	if messageID < 1 || messageID > maxSyncMLSessionMessages {
		return nil, ErrCSPCommand
	}
	return s.readCSPObservations(ctx, actor, scope, deviceID, commandID, messageID, 0, 1)
}

func (s *Store) readCSPObservations(ctx context.Context, actor string, scope access.Scope, deviceID, commandID string, messageID, offset, limit int) (*CSPObservationHistory, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !canonicalInvitationID(commandID) {
		return nil, ErrCSPCommand
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeCSPConsole(ctx, tx, actor, scope, deviceID, false); err != nil {
		return nil, err
	}
	c, err := scanCSPCommand(tx.QueryRowContext(ctx, `SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR SHARE`, commandID, deviceID, scope.TenantID, scope.SiteID))
	if err != nil {
		return nil, err
	}
	plain, command, err := s.openCSPRequest(c)
	clear(plain)
	if err != nil {
		return nil, err
	}
	current, err := s.openCSPResult(c)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT o.session_id,o.message_id,o.created_at,o.request_digest,o.encrypted_observation,p.request_digest
		FROM mdm_windows_csp_observations o LEFT JOIN mdm_windows_syncml_packets p
		ON p.session_id=o.session_id AND p.device_id=o.device_id AND p.tenant_id=o.tenant_id AND p.site_id=o.site_id AND p.message_id=o.message_id
		WHERE o.command_id=$1 AND o.device_id=$2 AND o.tenant_id=$3 AND o.site_id=$4 AND ($5::integer=0 OR o.message_id=$5)
		ORDER BY o.message_id LIMIT $6 OFFSET $7`, commandID, deviceID, scope.TenantID, scope.SiteID, messageID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	history := &CSPObservationHistory{Command: c.CSPCommand, Observations: []CSPObservation{}}
	for rows.Next() {
		observation, err := s.openCSPObservation(c, command, current, rows)
		if err != nil {
			return nil, err
		}
		if messageID == 0 {
			observation.Outcomes = nil
		}
		history.Observations = append(history.Observations, *observation)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if messageID != 0 && len(history.Observations) != 1 {
		return nil, ErrNotFound
	}
	if err := auditCSP(ctx, tx, c, actor, "command.read"); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return history, nil
}

// openCSPObservation is shared by console reads and exports. It authenticates
// packet provenance and the dispatched operation tree before exposing values.
func (s *Store) openCSPObservation(c *cspStoredCommand, command SyncMLCommand, current *cspStoredResult, row cspScanner) (*CSPObservation, error) {
	var observation CSPObservation
	var digest, encrypted, packetDigest []byte
	if err := row.Scan(&observation.SessionID, &observation.MessageID, &observation.ReceivedAt, &digest, &encrypted, &packetDigest); err != nil {
		return nil, err
	}
	if observation.SessionID != c.DeliveredSessionID || observation.MessageID <= c.DeliveredMessage || observation.MessageID > maxSyncMLSessionMessages || c.DeliveredAt == nil || observation.ReceivedAt.Before(*c.DeliveredAt) || len(digest) != 32 || !bytes.Equal(digest, packetDigest) {
		return nil, ErrAuthoritySecret
	}
	plain, err := s.secrets.openBounded(encrypted, cspObservationPurpose(c, observation.SessionID, strconv.Itoa(observation.MessageID), digest, observation.ReceivedAt), maxCSPProtectedBytes)
	if err != nil {
		return nil, err
	}
	var state cspSessionCommand
	err = decodeSyncMLProtectedJSON(plain, &state)
	clear(plain)
	if err != nil || state.validate() != nil || state.CommandID != c.ID || state.UnenrollmentRequestID != c.UnenrollmentRequestID || state.MessageID != strconv.Itoa(c.DeliveredMessage) || state.ObservedMessageID != strconv.Itoa(observation.MessageID) || len(state.StopReason) > 128 {
		return nil, ErrAuthoritySecret
	}
	if err := bindCSPDispatch(&syncMLSession{ID: observation.SessionID}, command, &state); err != nil {
		return nil, err
	}
	if current.Exchange == nil || len(current.Exchange.Operations) != len(state.Operations) {
		return nil, ErrAuthoritySecret
	}
	for n, operation := range state.Operations {
		if operation.WireID != current.Exchange.Operations[n].WireID {
			return nil, ErrAuthoritySecret
		}
	}
	observation.Outcome, observation.StopReason = cspOutcome(&state), state.StopReason
	observation.Outcomes = cspOperationOutcomes(&state)
	return &observation, nil
}
