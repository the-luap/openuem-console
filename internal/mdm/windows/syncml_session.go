package windows

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	maxSyncMLSessionMessages   = 64
	maxSyncMLSessionStateBytes = 2 << 20
	syncMLSessionLifetime      = 15 * time.Minute
	maxSyncMLDeviceInfoBytes   = 4096
)

var (
	ErrSyncMLSession        = errors.New("native Windows SyncML session could not be accepted")
	ErrSyncMLReplay         = errors.New("native Windows SyncML message conflicts with its recorded exchange")
	ErrSyncMLSessionExpired = errors.New("native Windows SyncML session is expired")
	ErrSyncMLMessageSize    = errors.New("native Windows SyncML response exceeds the negotiated message size")
)

type syncMLDeviceNonces struct {
	Version     int
	ClientNonce string
	ServerNonce string
}

type syncMLSentCommand struct{ ID, Kind string }

type syncMLIdentityProbe struct {
	MessageID string
	CommandID string
	Status    string
	Data      string
	HasResult bool
	MoreData  bool
}

type syncMLIncomingChunk struct {
	Kind string
	URI  string
	Size uint64
}

type syncMLSessionState struct {
	Version                    int
	SourceURI                  string
	ClientAuthenticated        bool
	ServerAuthenticated        bool
	ServerVerified             bool
	ClientChallenges           int
	ServerChallenges           int
	ClientNonce                string
	ServerNonce                string
	MaximumResponseBytes       uint64
	MaximumResponseObjectBytes uint64
	DeviceInfo                 map[string]string
	IncompleteInfo             map[string]bool
	LastServerCredential       bool
	LastResponse               []syncMLSentCommand
	Probe                      *syncMLIdentityProbe
	IncomingChunk              *syncMLIncomingChunk
	LoginStatus                string
	CSP                        *cspSessionCommand
}

type syncMLSession struct {
	ID          string
	WireID      string
	Phase       string
	Revision    int64
	LastMessage int
	CreatedAt   time.Time
	ExpiresAt   time.Time
	State       syncMLSessionState
}

type syncMLDeviceRecord struct {
	Revision        int64
	ActiveSessionID string
	CreatedAt       time.Time
	Nonces          syncMLDeviceNonces
}

func (syncMLDeviceNonces) String() string      { return "[protected Windows SyncML nonces]" }
func (v syncMLDeviceNonces) GoString() string  { return v.String() }
func (syncMLSessionState) String() string      { return "[protected Windows SyncML session state]" }
func (v syncMLSessionState) GoString() string  { return v.String() }
func (syncMLSession) String() string           { return "[protected Windows SyncML session]" }
func (v syncMLSession) GoString() string       { return v.String() }
func (syncMLDeviceRecord) String() string      { return "[protected Windows SyncML device state]" }
func (v syncMLDeviceRecord) GoString() string  { return v.String() }
func (syncMLIdentityProbe) String() string     { return "[protected Windows SyncML identity probe]" }
func (v syncMLIdentityProbe) GoString() string { return v.String() }
func (syncMLIncomingChunk) String() string     { return "[protected Windows SyncML incomplete object]" }
func (v syncMLIncomingChunk) GoString() string { return v.String() }

func decodeSyncMLProtectedJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrAuthoritySecret
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ErrAuthoritySecret
	}
	return nil
}

func newSyncMLNonce() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", ErrSyncMLSession
	}
	defer clear(value[:])
	return base64.StdEncoding.EncodeToString(value[:]), nil
}

func (v syncMLDeviceNonces) validate() error {
	if v.Version != 1 {
		return ErrAuthoritySecret
	}
	for _, nonce := range []string{v.ClientNonce, v.ServerNonce} {
		data, err := decodeSyncMLNonce(nonce)
		clear(data)
		if err != nil {
			return ErrAuthoritySecret
		}
	}
	return nil
}

func syncMLTerminal(phase string) bool {
	return phase == "completed" || phase == "failed" || phase == "aborted" || phase == "expired"
}

func syncMLStoredIdentifier(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && validSyncMLXMLText(value) && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}

func (s *syncMLSession) validate() error {
	v := &s.State
	if !canonicalInvitationID(s.ID) || !syncMLStoredIdentifier(s.WireID, 64) || (!syncMLTerminal(s.Phase) && s.Phase != "authenticating" && s.Phase != "active") || s.Revision <= 0 || s.LastMessage < 1 || s.LastMessage > maxSyncMLSessionMessages || s.CreatedAt.IsZero() || !s.ExpiresAt.After(s.CreatedAt) || s.ExpiresAt.Sub(s.CreatedAt) > syncMLSessionLifetime {
		return ErrAuthoritySecret
	}
	if v.Version != 1 || !syncMLStoredIdentifier(v.SourceURI, 2048) || v.ClientChallenges < 0 || v.ClientChallenges > 1 || v.ServerChallenges < 0 || v.ServerChallenges > 1 || v.MaximumResponseBytes == 0 || v.MaximumResponseBytes > MaxSyncMLBytes || v.DeviceInfo == nil || v.IncompleteInfo == nil || len(v.DeviceInfo) > len(syncMLRequiredDeviceInfo) || len(v.IncompleteInfo) != len(v.DeviceInfo) || len(v.LastResponse) == 0 || len(v.LastResponse) > MaxSyncMLCommands {
		return ErrAuthoritySecret
	}
	if v.LoginStatus != "" && v.LoginStatus != "user" && v.LoginStatus != "others" && v.LoginStatus != "none" || v.CSP.validate() != nil {
		return ErrAuthoritySecret
	}
	if v.MaximumResponseObjectBytes > MaxCSPRequestBytes {
		return ErrAuthoritySecret
	}
	if (syncMLDeviceNonces{Version: 1, ClientNonce: v.ClientNonce, ServerNonce: v.ServerNonce}).validate() != nil || v.ServerAuthenticated && !v.ServerVerified || s.Phase == "active" && (!v.ClientAuthenticated || !v.ServerVerified) {
		return ErrAuthoritySecret
	}
	for uri, value := range v.DeviceInfo {
		if !syncMLDeviceInfoURI(uri) || !validSyncMLXMLText(value) || len(value) > maxSyncMLDeviceInfoBytes {
			return ErrAuthoritySecret
		}
		if _, ok := v.IncompleteInfo[uri]; !ok {
			return ErrAuthoritySecret
		}
	}
	if chunk := v.IncomingChunk; chunk != nil {
		if chunk.Size == 0 || chunk.Size > maxSyncMLDeviceInfoBytes || !syncMLDeviceInfoURI(chunk.URI) {
			return ErrAuthoritySecret
		}
		switch chunk.Kind {
		case "Replace":
			if !v.IncompleteInfo[chunk.URI] || uint64(len(v.DeviceInfo[chunk.URI])) >= chunk.Size {
				return ErrAuthoritySecret
			}
		case "Results":
			if chunk.URI != "./DevInfo/DevId" || v.Probe == nil || !v.Probe.MoreData || uint64(len(v.Probe.Data)) >= chunk.Size {
				return ErrAuthoritySecret
			}
		default:
			return ErrAuthoritySecret
		}
	}
	for n, sent := range v.LastResponse {
		if sent.ID != syncMLResponseCommandID(s, strconv.Itoa(s.LastMessage), n) {
			return ErrAuthoritySecret
		}
		switch sent.Kind {
		case "Status", "Get", "Alert", "Add", "Replace", "Delete", "Exec", "Atomic", "Sequence":
		default:
			return ErrAuthoritySecret
		}
	}
	if p := v.Probe; p != nil {
		messageID, err := strconv.Atoi(p.MessageID)
		if err != nil || messageID < 1 || messageID > s.LastMessage || strconv.Itoa(messageID) != p.MessageID || !syncMLStoredIdentifier(p.CommandID, 64) || len(p.Data) > maxSyncMLDeviceInfoBytes || !validSyncMLXMLText(p.Data) || !p.HasResult && (p.MoreData || p.Data != "") {
			return ErrAuthoritySecret
		}
		if p.Status != "" {
			code, err := strconv.Atoi(p.Status)
			if err != nil || code < 100 || code > 999 || strconv.Itoa(code) != p.Status {
				return ErrAuthoritySecret
			}
		}
		if p.HasResult && !p.MoreData && p.Data != v.DeviceInfo["./DevInfo/DevId"] {
			return ErrAuthoritySecret
		}
	}
	return nil
}

func syncMLSessionPurpose(kind string, identity ManagementDeviceIdentity, options EnrollmentOptions, session *syncMLSession, revision int64) string {
	base := fmt.Sprintf("openuem/windows/syncml/%s/v1/%d/%d/%s/%s/%s/%s/%x", kind, identity.TenantID, identity.SiteID, identity.DeviceID, identity.CertificateID, identity.AuthorityID, identity.FingerprintSHA256, enrollmentConfigurationDigest(options))
	if session != nil {
		base += fmt.Sprintf("/%s/%x/%s/%d/%s/%s", session.ID, []byte(session.WireID), session.Phase, session.LastMessage, session.CreatedAt.UTC().Format(time.RFC3339Nano), session.ExpiresAt.UTC().Format(time.RFC3339Nano))
	}
	return base + "/" + strconv.FormatInt(revision, 10)
}

func syncMLDevicePurpose(identity ManagementDeviceIdentity, options EnrollmentOptions, record syncMLDeviceRecord) string {
	return syncMLSessionPurpose("nonces", identity, options, nil, record.Revision) + "/" + record.ActiveSessionID + "/" + record.CreatedAt.UTC().Format(time.RFC3339Nano)
}

func syncMLPacketPurpose(identity ManagementDeviceIdentity, options EnrollmentOptions, sessionID string, messageID int, requestDigest, responseDigest []byte) string {
	return syncMLSessionPurpose("response", identity, options, nil, 0) + fmt.Sprintf("/%s/%d/%x/%x", sessionID, messageID, requestDigest, responseDigest)
}
