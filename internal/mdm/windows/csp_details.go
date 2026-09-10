package windows

import (
	"context"

	"github.com/open-uem/openuem-console/internal/security/access"
)

type CSPOperationOutcome struct {
	CommandID     string      `json:"-" xml:"-"`
	ParentID      string      `json:"-" xml:"-"`
	Kind          string      `json:"-" xml:"-"`
	URI           string      `json:"-" xml:"-"`
	Status        int         `json:"-" xml:"-"`
	OriginalError string      `json:"-" xml:"-"`
	Incomplete    bool        `json:"-" xml:"-"`
	Format        string      `json:"-" xml:"-"`
	MIME          string      `json:"-" xml:"-"`
	Data          *SyncMLData `json:"-" xml:"-"`
}

type CSPCommandDetail struct {
	Command    CSPCommand            `json:"-" xml:"-"`
	Request    SyncMLCommand         `json:"-" xml:"-"`
	Reason     string                `json:"-" xml:"-"`
	Resolution string                `json:"-" xml:"-"`
	Outcomes   []CSPOperationOutcome `json:"-" xml:"-"`
}

func (CSPCommandDetail) String() string        { return "[protected Windows CSP command details]" }
func (v CSPCommandDetail) GoString() string    { return v.String() }
func (CSPOperationOutcome) String() string     { return "[protected Windows CSP operation outcome]" }
func (v CSPOperationOutcome) GoString() string { return v.String() }

// CSPCommandDetails is an audited, currently authorized payload read. Result data
// remains untrusted device content; views must escape it and never execute it.
func (s *Store) CSPCommandDetails(ctx context.Context, actor string, scope access.Scope, deviceID, commandID string) (*CSPCommandDetail, error) {
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
	result, err := s.openCSPResult(c)
	if err != nil {
		return nil, err
	}
	detail := &CSPCommandDetail{Command: c.CSPCommand, Request: command, Reason: result.Reason, Resolution: result.Resolution, Outcomes: []CSPOperationOutcome{}}
	detail.Outcomes = cspOperationOutcomes(result.Exchange)
	if err := auditCSP(ctx, tx, c, actor, "command.read"); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return detail, nil
}

// AbandonCSPCommand acknowledges an uncertain outcome and releases the device's
// queue. It does not undo, retry or declare successful the original operation.
func (s *Store) AbandonCSPCommand(ctx context.Context, actor string, scope access.Scope, deviceID, commandID string, expectedRevision int64, resolution string) error {
	if s == nil || s.db == nil {
		return ErrStore
	}
	if s.secrets == nil {
		return ErrMasterKey
	}
	if !canonicalInvitationID(commandID) || expectedRevision < 1 || !validEnrollmentUsername(resolution) {
		return ErrCSPCommand
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.authorizeCSPConsole(ctx, tx, actor, scope, deviceID, true); err != nil {
		return err
	}
	c, err := scanCSPCommand(tx.QueryRowContext(ctx, `SELECT `+cspCommandColumns+` FROM mdm_windows_csp_commands WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR UPDATE`, commandID, deviceID, scope.TenantID, scope.SiteID))
	if err != nil {
		return err
	}
	if c.UnenrollmentRequestID != "" {
		return ErrUnenrollmentRequest
	}
	if c.Revision != expectedRevision {
		return ErrCSPConflict
	}
	if c.Phase != "unknown" {
		return ErrCSPAlreadySent
	}
	result, err := s.openCSPResult(c)
	if err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&c.UpdatedAt); err != nil {
		return err
	}
	c.Revision++
	c.Phase = "abandoned"
	c.CompletedAt = &c.UpdatedAt
	result.Reason = "abandoned"
	result.Resolution = resolution
	if err := s.writeCSPResult(ctx, tx, c, *result); err != nil {
		return err
	}
	if err := auditCSP(ctx, tx, c, actor, "command.abandoned"); err != nil {
		return err
	}
	return tx.Commit()
}
