package windows

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

const maxCSPExportBytes = 32 << 20

var (
	ErrCSPExportTooLarge = errors.New("Windows CSP evidence export exceeds its size limit")
	ErrCSPExportBusy     = errors.New("Windows CSP evidence export is busy")
)

// CSPCommandExport is an explicit plaintext download, never a log or ordinary
// serialized response. The caller must clear Data after writing the attachment.
type CSPCommandExport struct {
	Data []byte `json:"-" xml:"-" yaml:"-"`
}

func (CSPCommandExport) String() string     { return "[protected Windows CSP evidence export]" }
func (v CSPCommandExport) GoString() string { return v.String() }

// Only these private DTOs intentionally serialize protected command content.
// Do not add wire credentials, packet bodies, request salts or ciphertext here.
type cspExportPrivate struct{}

func (cspExportPrivate) String() string     { return "[protected Windows CSP export content]" }
func (v cspExportPrivate) GoString() string { return v.String() }

type cspExportValue struct {
	cspExportPrivate
	Representation string `json:"representation"`
	Value          string `json:"value"`
}

type cspExportIntent struct {
	cspExportPrivate
	ID       string            `json:"operation_id"`
	Kind     string            `json:"kind"`
	URI      string            `json:"target,omitempty"`
	Format   string            `json:"format,omitempty"`
	MIME     string            `json:"mime,omitempty"`
	Data     *cspExportValue   `json:"data"`
	Children []cspExportIntent `json:"children"`
}

type cspExportOutcome struct {
	cspExportPrivate
	CommandID     string          `json:"command_id"`
	ParentID      string          `json:"parent_id"`
	Kind          string          `json:"kind"`
	URI           string          `json:"target"`
	Status        *int            `json:"status"`
	OriginalError string          `json:"original_error"`
	Incomplete    bool            `json:"incomplete"`
	Format        string          `json:"format"`
	MIME          string          `json:"mime"`
	Data          *cspExportValue `json:"data"`
}

type cspExportMetadata struct {
	cspExportPrivate
	ID                    string     `json:"id"`
	DeviceID              string     `json:"device_id"`
	TenantID              int        `json:"organization_id"`
	SiteID                int        `json:"site_id"`
	RequestKey            string     `json:"request_id"`
	CreatedBy             string     `json:"created_by"`
	CreatedByRevision     int64      `json:"creator_permission_revision"`
	UserTarget            bool       `json:"user_target"`
	Revision              int64      `json:"revision"`
	Phase                 string     `json:"phase"`
	CreatedAt             time.Time  `json:"created_at"`
	ExpiresAt             time.Time  `json:"expires_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
	DeliveredSessionID    string     `json:"delivered_session_id"`
	DeliveredMessage      int        `json:"delivered_message"`
	DeliveredAt           *time.Time `json:"delivered_at"`
	CompletedAt           *time.Time `json:"completed_at"`
	UpdateRunID           string     `json:"update_run_id,omitempty"`
	UpdateStep            int        `json:"update_step"`
	UnenrollmentRequestID string     `json:"disconnection_request_id,omitempty"`
}

type cspExportResult struct {
	cspExportPrivate
	Reason     string             `json:"reason"`
	Resolution string             `json:"resolution"`
	Outcomes   []cspExportOutcome `json:"operations"`
}

type cspExportHeader struct {
	cspExportPrivate
	Schema          string            `json:"schema"`
	SchemaVersion   int               `json:"schema_version"`
	AuditID         int64             `json:"audit_id"`
	ExportedAt      time.Time         `json:"exported_at"`
	HistoryComplete bool              `json:"history_complete"`
	SelectedMessage int               `json:"selected_message,omitempty"`
	Command         cspExportMetadata `json:"command"`
	Request         cspExportIntent   `json:"request"`
	CurrentResult   cspExportResult   `json:"current_result"`
}

type cspExportObservation struct {
	cspExportPrivate
	SessionID  string             `json:"session_id"`
	MessageID  int                `json:"message_id"`
	ReceivedAt time.Time          `json:"received_at"`
	Outcome    string             `json:"outcome"`
	StopReason string             `json:"stop_reason"`
	Outcomes   []cspExportOutcome `json:"operations"`
}

func cspExportData(data *SyncMLData) *cspExportValue {
	if data == nil {
		return nil
	}
	if data.XML != "" {
		return &cspExportValue{Representation: "xml", Value: data.XML}
	}
	return &cspExportValue{Representation: "text", Value: data.Text}
}

func cspExportRequest(command SyncMLCommand) cspExportIntent {
	value := cspExportIntent{ID: command.ID, Kind: command.Kind, Children: []cspExportIntent{}}
	if len(command.Items) == 1 {
		item := command.Items[0]
		if item.Target != nil {
			value.URI = item.Target.URI
		}
		if item.Meta != nil {
			value.Format, value.MIME = item.Meta.Format, item.Meta.Type
		}
		value.Data = cspExportData(item.Data)
	}
	for _, child := range command.Commands {
		value.Children = append(value.Children, cspExportRequest(child))
	}
	return value
}

func cspExportOutcomes(outcomes []CSPOperationOutcome) []cspExportOutcome {
	values := make([]cspExportOutcome, 0, len(outcomes))
	for _, outcome := range outcomes {
		value := cspExportOutcome{CommandID: outcome.CommandID, ParentID: outcome.ParentID, Kind: outcome.Kind, URI: outcome.URI, OriginalError: outcome.OriginalError, Incomplete: outcome.Incomplete, Format: outcome.Format, MIME: outcome.MIME}
		if outcome.Status != 0 {
			status := outcome.Status
			value.Status = &status
		}
		if !outcome.Incomplete {
			value.Data = cspExportData(outcome.Data)
		}
		values = append(values, value)
	}
	return values
}

func cspExportTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	stamp := value.UTC()
	return &stamp
}

// The buffer never streams bytes to a caller before every integrity check and
// the export audit commit have succeeded. Each snapshot is decoded separately.
type cspExportBuffer struct {
	cspExportPrivate
	ctx   context.Context
	limit int
	data  []byte
}

func (b *cspExportBuffer) Write(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > b.limit-len(b.data) {
		return 0, ErrCSPExportTooLarge
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

// ExportCSPCommand downloads a coherent, authenticated revision. messageID=0
// includes all stored observations; 1..64 selects one historical snapshot.
// Complete values may contain secrets. This is evidence, not an import format.
func (s *Store) ExportCSPCommand(ctx context.Context, actor string, scope access.Scope, deviceID, commandID string, expectedRevision int64, messageID int) (*CSPCommandExport, error) {
	return s.exportCSPCommand(ctx, actor, scope, deviceID, commandID, expectedRevision, messageID, maxCSPExportBytes)
}

func (s *Store) exportCSPCommand(ctx context.Context, actor string, scope access.Scope, deviceID, commandID string, expectedRevision int64, messageID, byteLimit int) (*CSPCommandExport, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !canonicalInvitationID(commandID) || expectedRevision < 1 || messageID < 0 || messageID > maxSyncMLSessionMessages || byteLimit < 1 || byteLimit > maxCSPExportBytes {
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
	// One export at a time across replicas bounds aggregate decoding work.
	var admitted bool
	if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(684627957)`).Scan(&admitted); err != nil {
		return nil, err
	}
	if !admitted {
		return nil, ErrCSPExportBusy
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
	if c.Revision != expectedRevision {
		return nil, ErrCSPConflict
	}
	// Match the latest operation tree as well as each historical snapshot.
	if current.Exchange != nil {
		if err := bindCSPDispatch(&syncMLSession{ID: c.DeliveredSessionID}, command, current.Exchange); err != nil {
			return nil, err
		}
	}
	header := cspExportHeader{Schema: "openuem.windows.csp-evidence", SchemaVersion: 1, HistoryComplete: messageID == 0, SelectedMessage: messageID,
		Command: cspExportMetadata{ID: c.ID, DeviceID: c.DeviceID, TenantID: c.TenantID, SiteID: c.SiteID, RequestKey: c.RequestKey, CreatedBy: c.CreatedBy, CreatedByRevision: c.CreatedByRevision, UserTarget: c.UserTarget, Revision: c.Revision, Phase: c.Phase, CreatedAt: c.CreatedAt.UTC(), ExpiresAt: c.ExpiresAt.UTC(), UpdatedAt: c.UpdatedAt.UTC(), DeliveredSessionID: c.DeliveredSessionID, DeliveredMessage: c.DeliveredMessage, DeliveredAt: cspExportTime(c.DeliveredAt), CompletedAt: cspExportTime(c.CompletedAt), UpdateRunID: c.UpdateRunID, UpdateStep: c.UpdateStep, UnenrollmentRequestID: c.UnenrollmentRequestID},
		Request: cspExportRequest(command), CurrentResult: cspExportResult{Reason: current.Reason, Resolution: current.Resolution, Outcomes: cspExportOutcomes(cspOperationOutcomes(current.Exchange))}}
	action := "command.exported"
	if messageID != 0 {
		action = "command.observation_exported"
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO mdm_windows_csp_audit(command_id,device_id,tenant_id,site_id,actor,action) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,created_at`, c.ID, c.DeviceID, c.TenantID, c.SiteID, actor, action).Scan(&header.AuditID, &header.ExportedAt); err != nil {
		return nil, err
	}
	header.ExportedAt = header.ExportedAt.UTC()
	b := &cspExportBuffer{ctx: ctx, limit: byteLimit}
	defer func() { clear(b.data) }()
	head, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	defer clear(head)
	if _, err := b.Write(head[:len(head)-1]); err != nil {
		return nil, err
	}
	if _, err := b.Write([]byte(",\"observations\":[")); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT o.session_id,o.message_id,o.created_at,o.request_digest,o.encrypted_observation,p.request_digest
		FROM mdm_windows_csp_observations o LEFT JOIN mdm_windows_syncml_packets p
		ON p.session_id=o.session_id AND p.device_id=o.device_id AND p.tenant_id=o.tenant_id AND p.site_id=o.site_id AND p.message_id=o.message_id
		WHERE o.command_id=$1 AND o.device_id=$2 AND o.tenant_id=$3 AND o.site_id=$4 AND ($5::integer=0 OR o.message_id=$5)
		ORDER BY o.message_id LIMIT 65`, c.ID, c.DeviceID, c.TenantID, c.SiteID, messageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	count, previous := 0, 0
	encoder := json.NewEncoder(b)
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		observation, err := s.openCSPObservation(c, command, current, rows)
		if err != nil {
			return nil, err
		}
		if observation.MessageID <= previous || count >= maxSyncMLSessionMessages {
			return nil, ErrAuthoritySecret
		}
		previous = observation.MessageID
		if count > 0 {
			if _, err := b.Write([]byte(",")); err != nil {
				return nil, err
			}
		}
		if err := encoder.Encode(cspExportObservation{SessionID: observation.SessionID, MessageID: observation.MessageID, ReceivedAt: observation.ReceivedAt.UTC(), Outcome: observation.Outcome, StopReason: observation.StopReason, Outcomes: cspExportOutcomes(observation.Outcomes)}); err != nil {
			return nil, err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if messageID != 0 && count != 1 {
		return nil, ErrNotFound
	}
	if _, err := b.Write([]byte("],\"observation_count\":" + strconv.Itoa(count) + "}\n")); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	data := b.data
	b.data = nil
	return &CSPCommandExport{Data: data}, nil
}
