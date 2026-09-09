package windows

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// processSyncML accepts only a direct TLS leaf supplied by the HTTP boundary.
// Identity, scope, protected state, response and audit share one transaction.
// Parsing here binds the transition to the exact bytes used for replay detection.
func (s *Store) processSyncML(ctx context.Context, certificate *x509.Certificate, data []byte, options EnrollmentOptions) ([]byte, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	request, err := ParseSyncML(data)
	if err != nil {
		return nil, err
	}
	messageID, err := strconv.Atoi(request.Header.MessageID)
	if err != nil || messageID > maxSyncMLSessionMessages {
		return nil, ErrSyncMLSession
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Use the same permission-before-scope lock order as console enqueue and
	// cancellation. This does not require the device to have a console account.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock_shared(684627902)`); err != nil {
		return nil, err
	}
	device, err := s.authorizeManagementDevice(ctx, tx, certificate, options)
	if err != nil {
		return nil, err
	}
	identity := device.identity
	secrets, err := s.syncMLBootstrap(ctx, tx, identity, options)
	if err != nil {
		return nil, err
	}
	record, err := s.lockSyncMLDevice(ctx, tx, identity, options, secrets)
	if err != nil {
		return nil, err
	}
	var session *syncMLSession
	if record.ActiveSessionID != "" {
		session, err = s.lockSyncMLSession(ctx, tx, identity, options, record.ActiveSessionID)
		if err != nil {
			return nil, err
		}
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	if record.CreatedAt.After(now) {
		return nil, ErrAuthoritySecret
	}
	requestDigest := sha256.Sum256(data)
	if session != nil && session.WireID == request.Header.SessionID && messageID <= session.LastMessage {
		response, replayErr := s.replaySyncML(ctx, tx, identity, options, session, messageID, requestDigest[:])
		if replayErr == nil {
			command, err := s.authorizeCSPReplay(ctx, tx, identity, session.ID, messageID)
			if err != nil {
				return nil, err
			}
			if err := checkSyncMLSessionTime(ctx, tx, session); err != nil {
				return nil, err
			}
			if err := auditSyncML(ctx, tx, identity, session.ID, "message.replayed"); err != nil {
				return nil, err
			}
			if command != nil {
				if err := checkCSPDeadline(ctx, tx, command); err != nil {
					return nil, err
				}
			}
			if err := commitSyncML(ctx, tx, device, session); err != nil {
				return nil, err
			}
			return response, nil
		}
		// A wire SessionID can wrap. Reusing it with different first-message
		// bytes requires the current next-session digest and a finished/expired
		// predecessor; an old credential cannot reset the recorded exchange.
		if !errors.Is(replayErr, ErrSyncMLReplay) {
			return nil, replayErr
		}
		if messageID != 1 || (!syncMLTerminal(session.Phase) && session.ExpiresAt.After(now)) || !syncMLClientDigestValid(identity, request, secrets.ClientSecret, record.Nonces.ClientNonce) {
			return nil, ErrSyncMLReplay
		}
	} else if session != nil && session.WireID == request.Header.SessionID {
		if err := checkSyncMLSessionTime(ctx, tx, session); err != nil {
			return nil, err
		}
		if syncMLTerminal(session.Phase) {
			return nil, ErrSyncMLSession
		}
	}
	newSession := session == nil || session.WireID != request.Header.SessionID || messageID == 1
	events := []string{}
	if newSession {
		if messageID != 1 {
			return nil, ErrSyncMLSession
		}
		if session != nil && !syncMLTerminal(session.Phase) {
			if session.ExpiresAt.After(now) {
				return nil, ErrSyncMLSession
			}
			session.Phase = "expired"
			session.Revision++
			if err := s.stopCSPSession(ctx, tx, identity, session); err != nil {
				return nil, err
			}
			if err := s.saveSyncMLSession(ctx, tx, identity, options, session, false); err != nil {
				return nil, err
			}
			if err := auditSyncML(ctx, tx, identity, session.ID, "session.expired"); err != nil {
				return nil, err
			}
		}
		expires := now.Add(syncMLSessionLifetime)
		if identity.CertificateExpiry.Before(expires) {
			expires = identity.CertificateExpiry
		}
		if !expires.After(now) {
			return nil, ErrManagementIdentity
		}
		session = &syncMLSession{ID: uuid.NewString(), WireID: request.Header.SessionID, Phase: "authenticating", Revision: 1, CreatedAt: now, ExpiresAt: expires,
			State: syncMLSessionState{Version: 1, SourceURI: request.Header.Source.URI, ClientNonce: record.Nonces.ClientNonce, ServerNonce: record.Nonces.ServerNonce, MaximumResponseBytes: 5000, DeviceInfo: map[string]string{}, IncompleteInfo: map[string]bool{}}}
		events = append(events, "session.started")
	} else {
		session.Revision++
	}
	activeCommand, err := s.lockCurrentCSP(ctx, tx, identity, session)
	if err != nil {
		return nil, err
	}
	response, transitionEvents, err := advanceSyncMLSession(identity, options, record, session, request, secrets)
	if err != nil {
		return nil, err
	}
	if err := s.observeCSP(ctx, tx, identity, session, activeCommand, request.Header.MessageID, requestDigest[:]); err != nil {
		return nil, err
	}
	dispatched, err := s.dispatchCSP(ctx, tx, identity, session, response)
	if err != nil {
		return nil, err
	}
	if dispatched != nil {
		filtered := transitionEvents[:0]
		for _, event := range transitionEvents {
			if event != "session.completed" {
				filtered = append(filtered, event)
			}
		}
		transitionEvents = filtered
	}
	encoded, err := EncodeSyncML(response)
	if err != nil {
		return nil, err
	}
	if uint64(len(encoded)) > session.State.MaximumResponseBytes {
		return nil, ErrSyncMLMessageSize
	}
	if err := s.saveSyncMLSession(ctx, tx, identity, options, session, newSession); err != nil {
		return nil, err
	}
	record.Revision++
	record.ActiveSessionID = session.ID
	if err := s.saveSyncMLDevice(ctx, tx, identity, options, record); err != nil {
		return nil, err
	}
	if err := s.saveSyncMLPacket(ctx, tx, identity, options, session.ID, messageID, requestDigest[:], encoded); err != nil {
		return nil, err
	}
	for _, event := range append(events, transitionEvents...) {
		if err := auditSyncML(ctx, tx, identity, session.ID, event); err != nil {
			return nil, err
		}
	}
	if dispatched != nil {
		if err := checkCSPDeadline(ctx, tx, dispatched); err != nil {
			return nil, err
		}
	}
	if err := commitSyncML(ctx, tx, device, session); err != nil {
		return nil, err
	}
	return encoded, nil
}

func (s *Store) syncMLBootstrap(ctx context.Context, tx *sql.Tx, identity ManagementDeviceIdentity, options EnrollmentOptions) (*syncMLBootstrapSecrets, error) {
	var encrypted, requestDigest, configDigest []byte
	err := tx.QueryRowContext(ctx, `SELECT encrypted_auth,request_digest,configuration_digest FROM mdm_windows_enrollments WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND certificate_id=$4 FOR SHARE`, identity.DeviceID, identity.TenantID, identity.SiteID, identity.CertificateID).Scan(&encrypted, &requestDigest, &configDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrManagementIdentity
	}
	if err != nil {
		return nil, err
	}
	if len(requestDigest) != sha256.Size || !hmac.Equal(configDigest, enrollmentConfigurationDigest(options)) {
		return nil, ErrAuthoritySecret
	}
	fingerprint, err := hex.DecodeString(identity.FingerprintSHA256)
	if err != nil || len(fingerprint) != sha256.Size {
		return nil, ErrAuthoritySecret
	}
	purpose := enrollmentSecretPurpose("syncml-bootstrap", identity.TenantID, identity.SiteID, identity.DeviceID, identity.AuthorityID, fingerprint, requestDigest, configDigest)
	plain, err := s.secrets.open(encrypted, purpose)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var secrets syncMLBootstrapSecrets
	if decodeSyncMLProtectedJSON(plain, &secrets) != nil || secrets.validate() != nil {
		return nil, ErrAuthoritySecret
	}
	return &secrets, nil
}

func (s *Store) lockSyncMLDevice(ctx context.Context, tx *sql.Tx, identity ManagementDeviceIdentity, options EnrollmentOptions, secrets *syncMLBootstrapSecrets) (*syncMLDeviceRecord, error) {
	record := &syncMLDeviceRecord{Revision: 1, Nonces: syncMLDeviceNonces{Version: 1, ClientNonce: secrets.ClientNonce, ServerNonce: secrets.ServerNonce}}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&record.CreatedAt); err != nil {
		return nil, err
	}
	encrypted, err := s.sealSyncMLJSON(record.Nonces, syncMLDevicePurpose(identity, options, *record), maxAuthoritySecretBytes)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_windows_syncml_state(device_id,tenant_id,site_id,certificate_id,revision,encrypted_state,created_at) VALUES($1,$2,$3,$4,1,$5,$6) ON CONFLICT(device_id) DO NOTHING`, identity.DeviceID, identity.TenantID, identity.SiteID, identity.CertificateID, encrypted, record.CreatedAt)
	if err != nil {
		return nil, err
	}
	err = tx.QueryRowContext(ctx, `SELECT revision,COALESCE(active_session_id::text,''),encrypted_state,created_at FROM mdm_windows_syncml_state WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND certificate_id=$4 FOR UPDATE`, identity.DeviceID, identity.TenantID, identity.SiteID, identity.CertificateID).Scan(&record.Revision, &record.ActiveSessionID, &encrypted, &record.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrManagementIdentity
	}
	if err != nil {
		return nil, err
	}
	if record.Revision <= 0 || (record.ActiveSessionID != "" && !canonicalInvitationID(record.ActiveSessionID)) {
		return nil, ErrAuthoritySecret
	}
	plain, err := s.secrets.open(encrypted, syncMLDevicePurpose(identity, options, *record))
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	if decodeSyncMLProtectedJSON(plain, &record.Nonces) != nil || record.Nonces.validate() != nil {
		return nil, ErrAuthoritySecret
	}
	return record, nil
}

func (s *Store) lockSyncMLSession(ctx context.Context, tx *sql.Tx, identity ManagementDeviceIdentity, options EnrollmentOptions, id string) (*syncMLSession, error) {
	session := &syncMLSession{ID: id}
	var encrypted []byte
	err := tx.QueryRowContext(ctx, `SELECT wire_session_id,phase,revision,last_message,encrypted_state,created_at,expires_at FROM mdm_windows_syncml_sessions WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND certificate_id=$5 FOR UPDATE`, id, identity.DeviceID, identity.TenantID, identity.SiteID, identity.CertificateID).Scan(&session.WireID, &session.Phase, &session.Revision, &session.LastMessage, &encrypted, &session.CreatedAt, &session.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAuthoritySecret
	}
	if err != nil {
		return nil, err
	}
	plain, err := s.secrets.openBounded(encrypted, syncMLSessionPurpose("session", identity, options, session, session.Revision), maxSyncMLSessionStateBytes)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	if decodeSyncMLProtectedJSON(plain, &session.State) != nil || session.validate() != nil {
		return nil, ErrAuthoritySecret
	}
	return session, nil
}

func (s *Store) sealSyncMLJSON(value any, purpose string, maximum int) ([]byte, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return nil, ErrAuthoritySecret
	}
	defer clear(plain)
	return s.secrets.sealBounded(plain, purpose, maximum)
}

func (s *Store) saveSyncMLDevice(ctx context.Context, tx *sql.Tx, identity ManagementDeviceIdentity, options EnrollmentOptions, record *syncMLDeviceRecord) error {
	if record.Nonces.validate() != nil {
		return ErrAuthoritySecret
	}
	encrypted, err := s.sealSyncMLJSON(record.Nonces, syncMLDevicePurpose(identity, options, *record), maxAuthoritySecretBytes)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE mdm_windows_syncml_state SET revision=$5,active_session_id=$6,encrypted_state=$7 WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND certificate_id=$4 AND revision=$8`, identity.DeviceID, identity.TenantID, identity.SiteID, identity.CertificateID, record.Revision, record.ActiveSessionID, encrypted, record.Revision-1)
	return syncMLUpdated(result, err)
}

func (s *Store) saveSyncMLSession(ctx context.Context, tx *sql.Tx, identity ManagementDeviceIdentity, options EnrollmentOptions, session *syncMLSession, insert bool) error {
	if session.validate() != nil {
		return ErrAuthoritySecret
	}
	encrypted, err := s.sealSyncMLJSON(session.State, syncMLSessionPurpose("session", identity, options, session, session.Revision), maxSyncMLSessionStateBytes)
	if err != nil {
		return err
	}
	if insert {
		_, err = tx.ExecContext(ctx, `INSERT INTO mdm_windows_syncml_sessions(id,device_id,tenant_id,site_id,certificate_id,wire_session_id,phase,revision,last_message,encrypted_state,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, session.ID, identity.DeviceID, identity.TenantID, identity.SiteID, identity.CertificateID, session.WireID, session.Phase, session.Revision, session.LastMessage, encrypted, session.CreatedAt, session.ExpiresAt)
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE mdm_windows_syncml_sessions SET phase=$6,revision=$7,last_message=$8,encrypted_state=$9 WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND certificate_id=$5 AND revision=$10`, session.ID, identity.DeviceID, identity.TenantID, identity.SiteID, identity.CertificateID, session.Phase, session.Revision, session.LastMessage, encrypted, session.Revision-1)
	return syncMLUpdated(result, err)
}

func syncMLUpdated(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrSyncMLSession
	}
	return nil
}

func (s *Store) saveSyncMLPacket(ctx context.Context, tx *sql.Tx, identity ManagementDeviceIdentity, options EnrollmentOptions, sessionID string, messageID int, requestDigest, response []byte) error {
	digest := sha256.Sum256(response)
	encrypted, err := s.secrets.sealBounded(response, syncMLPacketPurpose(identity, options, sessionID, messageID, requestDigest, digest[:]), MaxSyncMLBytes)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_windows_syncml_packets(session_id,device_id,tenant_id,site_id,message_id,request_digest,response_digest,encrypted_response) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, sessionID, identity.DeviceID, identity.TenantID, identity.SiteID, messageID, requestDigest, digest[:], encrypted)
	return err
}

func (s *Store) replaySyncML(ctx context.Context, tx *sql.Tx, identity ManagementDeviceIdentity, options EnrollmentOptions, session *syncMLSession, messageID int, requestDigest []byte) ([]byte, error) {
	var storedRequest, storedResponse, encrypted []byte
	err := tx.QueryRowContext(ctx, `SELECT request_digest,response_digest,encrypted_response FROM mdm_windows_syncml_packets WHERE session_id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND message_id=$5 FOR SHARE`, session.ID, identity.DeviceID, identity.TenantID, identity.SiteID, messageID).Scan(&storedRequest, &storedResponse, &encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAuthoritySecret
	}
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(storedRequest, requestDigest) {
		return nil, ErrSyncMLReplay
	}
	response, err := s.secrets.openBounded(encrypted, syncMLPacketPurpose(identity, options, session.ID, messageID, storedRequest, storedResponse), MaxSyncMLBytes)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(response)
	message, err := ParseSyncML(response)
	if !hmac.Equal(storedResponse, digest[:]) || err != nil || message.Header.SessionID != session.WireID || message.Header.MessageID != strconv.Itoa(messageID) || message.Header.Target.URI != session.State.SourceURI || message.Header.Target.Name != identity.DeviceID || message.Header.Source.URI != options.ManagementURL || message.Header.Source.Name != options.ProviderID {
		clear(response)
		return nil, ErrAuthoritySecret
	}
	return response, nil
}

func auditSyncML(ctx context.Context, tx *sql.Tx, identity ManagementDeviceIdentity, sessionID, action string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_windows_management_audit(device_id,tenant_id,site_id,session_id,action) VALUES($1,$2,$3,$4,$5)`, identity.DeviceID, identity.TenantID, identity.SiteID, sessionID, action)
	return err
}

func checkSyncMLSessionTime(ctx context.Context, tx *sql.Tx, session *syncMLSession) error {
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if session.CreatedAt.After(now) || !session.ExpiresAt.After(now) {
		return ErrSyncMLSessionExpired
	}
	return nil
}

func commitSyncML(ctx context.Context, tx *sql.Tx, device *managementDevice, session *syncMLSession) error {
	if err := checkSyncMLSessionTime(ctx, tx, session); err != nil {
		return err
	}
	if err := checkManagementDeviceTime(ctx, tx, device); err != nil {
		return err
	}
	return tx.Commit()
}
