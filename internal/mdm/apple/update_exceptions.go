package apple

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrUpdateException          = errors.New("invalid Apple update exception")
	ErrUpdateExceptionActive    = errors.New("an active exception prevents update policy assignment")
	ErrUpdateExceptionReview    = errors.New("the reviewed Apple update exception state changed")
	ErrUpdateExceptionIntegrity = errors.New("Apple update exception evidence is unavailable")
)

type UpdateException struct {
	ID                    string        `json:"-" xml:"-" yaml:"-"`
	Scope                 Scope         `json:"-" xml:"-" yaml:"-"`
	DeviceID              string        `json:"-" xml:"-" yaml:"-"`
	ScopeRevision         int64         `json:"-" xml:"-" yaml:"-"`
	Revision              int           `json:"-" xml:"-" yaml:"-"`
	PreviousID            string        `json:"-" xml:"-" yaml:"-"`
	RequestKey            string        `json:"-" xml:"-" yaml:"-"`
	Actor                 string        `json:"-" xml:"-" yaml:"-"`
	ActorRevision         int64         `json:"-" xml:"-" yaml:"-"`
	Kind                  string        `json:"-" xml:"-" yaml:"-"`
	CreatedAt             time.Time     `json:"-" xml:"-" yaml:"-"`
	ExpiresAt             *time.Time    `json:"-" xml:"-" yaml:"-"`
	Reason                string        `json:"-" xml:"-" yaml:"-"`
	ReviewToken           string        `json:"-" xml:"-" yaml:"-"`
	PreviousPolicy        *UpdatePolicy `json:"-" xml:"-" yaml:"-"`
	NotificationAvailable bool          `json:"-" xml:"-" yaml:"-"`
	CommandID             string        `json:"-" xml:"-" yaml:"-"`
}

func (UpdateException) String() string     { return "[protected Apple update exception]" }
func (v UpdateException) GoString() string { return v.String() }

func (r *UpdateException) Active(at time.Time) bool {
	return r != nil && r.Kind == "pause" && r.ExpiresAt != nil && !r.CreatedAt.After(at) && r.ExpiresAt.After(at)
}

func validUpdateExceptionReason(reason string) bool {
	if len(reason) == 0 || len(reason) > 1024 || !utf8.ValidString(reason) || strings.TrimSpace(reason) != reason {
		return false
	}
	for _, ch := range reason {
		if unicode.IsControl(ch) && ch != '\n' && ch != '\t' {
			return false
		}
	}
	return true
}

type updateExceptionWire struct {
	Version                        int
	Reason, ReviewToken, CommandID string
	PreviousPolicy                 *updatePolicyGroupState
	NotificationAvailable          bool
}

const updateExceptionColumns = `id,tenant_id,site_id,device_id,scope_revision,revision,previous_id,request_key,CASE WHEN octet_length(actor)<=255 THEN actor ELSE NULL END,actor_revision,kind,created_at,expires_at,CASE WHEN octet_length(encrypted_intent)<=32796 THEN encrypted_intent ELSE NULL END`

func updateExceptionPurpose(r *UpdateException) string {
	expires := ""
	if r.ExpiresAt != nil {
		expires = r.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	return fmt.Sprintf("openuem/apple/update-exception/v1/%s/%d/%d/%s/%d/%s/%s/%x/%d/%s/%s/%s/%d", r.ID, r.Scope.TenantID, r.Scope.SiteID, r.DeviceID, r.Revision, r.PreviousID, r.RequestKey, sha256.Sum256([]byte(r.Actor)), r.ActorRevision, r.Kind, r.CreatedAt.UTC().Format(time.RFC3339Nano), expires, r.ScopeRevision)
}

func updateExceptionReviewToken(scope Scope, id string, policy *UpdatePolicy, previousID string, previousRevision int, notify bool, scopeRevision int64) string {
	return fmt.Sprintf("%x", sha256.Sum256(fmt.Appendf(nil, "openuem/apple/update-exception/review/v1/%s/%s/%d/%t/%d", updatePolicyGroupToken(scope, id, policy), previousID, previousRevision, notify, scopeRevision)))
}

func (s *Store) scanUpdateException(row scanner) (*UpdateException, error) {
	r := &UpdateException{}
	var previous sql.NullString
	var encrypted []byte
	if err := row.Scan(&r.ID, &r.Scope.TenantID, &r.Scope.SiteID, &r.DeviceID, &r.ScopeRevision, &r.Revision, &previous, &r.RequestKey, &r.Actor, &r.ActorRevision, &r.Kind, &r.CreatedAt, &r.ExpiresAt, &encrypted); err != nil {
		return nil, notFound(err)
	}
	r.PreviousID = previous.String
	plain, err := s.secrets.open(encrypted, updateExceptionPurpose(r))
	defer clear(plain)
	if err != nil || len(plain) > 32768 {
		return nil, ErrUpdateExceptionIntegrity
	}
	var wire updateExceptionWire
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(new(any)) != io.EOF || wire.Version != 1 || !validUpdateExceptionReason(wire.Reason) || !updateGroupPolicyToken.MatchString(wire.ReviewToken) || (wire.CommandID != "" && !profileRevisionUUID(wire.CommandID)) {
		return nil, ErrUpdateExceptionIntegrity
	}
	if r.ScopeRevision < 0 || r.Revision < 1 || r.Revision > 2147483647 || !profileRevisionUUID(r.ID) || !profileRevisionUUID(r.DeviceID) || !profileRevisionUUID(r.RequestKey) || (r.Revision == 1 && r.PreviousID != "") || (r.Revision > 1 && !profileRevisionUUID(r.PreviousID)) {
		return nil, ErrUpdateExceptionIntegrity
	}
	switch r.Kind {
	case "pause":
		if r.ExpiresAt == nil || !r.ExpiresAt.After(r.CreatedAt) || r.ExpiresAt.After(r.CreatedAt.Add(30*24*time.Hour)) || (wire.NotificationAvailable != (wire.CommandID != "")) {
			return nil, ErrUpdateExceptionIntegrity
		}
	case "resume":
		if r.ExpiresAt != nil || wire.CommandID != "" || r.PreviousID == "" {
			return nil, ErrUpdateExceptionIntegrity
		}
	default:
		return nil, ErrUpdateExceptionIntegrity
	}
	if wire.PreviousPolicy != nil {
		r.PreviousPolicy = &UpdatePolicy{DeviceID: r.DeviceID, TargetVersion: wire.PreviousPolicy.TargetVersion, TargetBuild: wire.PreviousPolicy.TargetBuild, Deadline: wire.PreviousPolicy.Deadline, DetailsURL: wire.PreviousPolicy.DetailsURL}
	}
	r.Reason, r.ReviewToken, r.CommandID, r.NotificationAvailable = wire.Reason, wire.ReviewToken, wire.CommandID, wire.NotificationAvailable
	if r.ReviewToken != updateExceptionReviewToken(r.Scope, r.DeviceID, r.PreviousPolicy, r.PreviousID, r.Revision-1, r.NotificationAvailable, r.ScopeRevision) {
		return nil, ErrUpdateExceptionIntegrity
	}
	return r, nil
}

func (s *Store) sealUpdateException(r *UpdateException) ([]byte, error) {
	wire := updateExceptionWire{Version: 1, Reason: r.Reason, ReviewToken: r.ReviewToken, CommandID: r.CommandID, NotificationAvailable: r.NotificationAvailable}
	if p := r.PreviousPolicy; p != nil {
		wire.PreviousPolicy = &updatePolicyGroupState{TargetVersion: p.TargetVersion, TargetBuild: p.TargetBuild, Deadline: p.Deadline, DetailsURL: p.DetailsURL}
	}
	plain, err := json.Marshal(wire)
	defer clear(plain)
	if err != nil {
		return nil, err
	}
	if len(plain) > 32768 {
		return nil, ErrUpdateException
	}
	return s.secrets.seal(plain, updateExceptionPurpose(r))
}

// The caller holds the native device lock. Exception scope follows this exact
// organization/site and enrollment; re-enrollment never inherits another ID.
func (s *Store) lastUpdateException(ctx context.Context, tx *sql.Tx, scope Scope, id string) (*UpdateException, error) {
	r, err := s.scanUpdateException(tx.QueryRowContext(ctx, `SELECT `+updateExceptionColumns+` FROM mdm_apple_update_exceptions WHERE tenant_id=$1 AND site_id=$2 AND device_id=$3 ORDER BY revision DESC LIMIT 1`, scope.TenantID, scope.SiteID, id))
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return r, err
}

// Site changes invalidate applicability permanently, including a move back.
// Historical events remain available only in their original scope.
func (s *Store) currentUpdateException(ctx context.Context, tx *sql.Tx, scope Scope, id string) (*UpdateException, error) {
	r, err := s.lastUpdateException(ctx, tx, scope, id)
	if err != nil || r == nil {
		return r, err
	}
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT update_exception_scope_revision FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND site_id=$3`, id, scope.TenantID, scope.SiteID).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if r.ScopeRevision != revision {
		return nil, nil
	}
	return r, nil
}

func (s *Store) requireNoUpdateException(ctx context.Context, tx *sql.Tx, d *Device) error {
	r, err := s.currentUpdateException(ctx, tx, Scope{TenantID: d.TenantID, SiteID: d.SiteID}, d.ID)
	if err != nil || r == nil {
		return err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if r.CreatedAt.After(now) {
		return ErrUpdateExceptionIntegrity
	}
	if r.Active(now) {
		return ErrUpdateExceptionActive
	}
	return nil
}
