package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"howett.net/plist"
)

var ErrUserChannelDeclined = errors.New("user-channel management is unavailable for this enrollment")

// UserChannel identifies the OS-reported user on one native enrollment. It is
// not a directory identity or proof of an interactive sign-in to an IdP.
// Push credentials and renewal candidates never enter this public read model.
type UserChannel struct {
	ID                string             `json:"id"`
	DeviceID          string             `json:"device_id"`
	UserID            string             `json:"user_id"`
	ShortName         string             `json:"short_name"`
	LongName          string             `json:"long_name"`
	Status            string             `json:"status"`
	PushStatus        string             `json:"push_status"`
	PushError         string             `json:"push_error"`
	TenantID          int                `json:"tenant_id"`
	SiteID            int                `json:"site_id"`
	NotOnConsole      bool               `json:"not_on_console"`
	FirstSeen         time.Time          `json:"first_seen"`
	LastSeen          time.Time          `json:"last_seen"`
	ProfilesAt        *time.Time         `json:"profiles_at"`
	InstalledProfiles []InstalledProfile `json:"installed_profiles"`
}

const userColumns = `id,tenant_id,site_id,device_id,user_id,short_name,long_name,status,not_on_console,first_seen,last_seen,profiles_at,installed_profiles,push_status,push_error`

func scanUser(row scanner) (*UserChannel, error) {
	var u UserChannel
	var profiles []byte
	err := row.Scan(&u.ID, &u.TenantID, &u.SiteID, &u.DeviceID, &u.UserID, &u.ShortName, &u.LongName, &u.Status, &u.NotOnConsole, &u.FirstSeen, &u.LastSeen, &u.ProfilesAt, &profiles, &u.PushStatus, &u.PushError)
	if err != nil {
		return nil, notFound(err)
	}
	if err = json.Unmarshal(profiles, &u.InstalledProfiles); err != nil {
		return nil, err
	}
	return &u, nil
}

func userMessageID(message map[string]any) (string, error) {
	for _, key := range []string{"EnrollmentID", "EnrollmentUserID", "AuthToken"} {
		if _, present := message[key]; present {
			return "", ErrUnauthorized
		}
	}
	id, err := uuid.Parse(stringValue(message, "UserID"))
	if err != nil || id == uuid.Nil || id.String() == "ffffffff-ffff-ffff-ffff-ffffffffffff" {
		return "", ErrUnauthorized
	}
	return id.String(), nil
}

func userChannelMessage(message map[string]any) bool {
	return stringValue(message, "MessageType") == "UserAuthenticate" || !deviceChannelMessage(message)
}

// The all-ones device marker is never an ordinary user identity. Only a Mac
// whose enrollment advertised per-user connections can use that marker, and it
// must not mix it with user-only metadata or an account-driven enrollment ID.
func normalizeDeviceMarker(d *Device, message map[string]any) map[string]any {
	if d == nil || d.Family() != PlatformMacOS || !d.PerUserConnections || strings.ToLower(stringValue(message, "UserID")) != "ffffffff-ffff-ffff-ffff-ffffffffffff" || stringValue(message, "MessageType") == "UserAuthenticate" {
		return message
	}
	clone := make(map[string]any, len(message)-1)
	for key, value := range message {
		if key != "UserID" {
			clone[key] = value
		}
	}
	if !deviceChannelMessage(clone) {
		return message
	}
	return clone
}

func (s *Store) lockUserParent(ctx context.Context, tx *sql.Tx, d *Device) (*Device, identityPeer, error) {
	if d == nil {
		return nil, identityPeer{}, ErrUnauthorized
	}
	current, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, d.ID, d.TenantID))
	if err != nil {
		return nil, identityPeer{}, err
	}
	peer, err := s.deviceIdentityPeer(ctx, tx, d)
	if err != nil {
		return nil, identityPeer{}, err
	}
	if peer.kind == "retired" {
		return nil, identityPeer{}, ErrUnauthorized
	}
	if (current.Status != "authenticating" && current.Status != "enrolled") || current.UDID == "" || current.UDID != d.UDID {
		return nil, identityPeer{}, ErrUnauthorized
	}
	if current.Family() != PlatformMacOS || !current.PerUserConnections {
		return nil, identityPeer{}, ErrUserChannelDeclined
	}
	var site int
	err = tx.QueryRowContext(ctx, `SELECT id FROM sites WHERE id=$1 AND tenant_sites=$2 FOR SHARE`, current.SiteID, current.TenantID).Scan(&site)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, identityPeer{}, ErrUnauthorized
	}
	if err != nil {
		return nil, identityPeer{}, err
	}
	return current, peer, nil
}

func validUserName(message map[string]any, key string, limit int) (string, error) {
	value, present := message[key]
	if !present {
		return "", nil
	}
	name, ok := value.(string)
	if !ok || !utf8.ValidString(name) || len(name) > limit || strings.ContainsAny(name, "\x00\r\n") {
		return "", ErrUnauthorized
	}
	return name, nil
}

func (s *Store) UserCheckIn(ctx context.Context, d *Device, message map[string]any) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if d == nil {
		return nil, ErrUnauthorized
	}
	userID, err := userMessageID(message)
	if err != nil || stringValue(message, "UDID") != d.UDID {
		return nil, ErrUnauthorized
	}
	kind := stringValue(message, "MessageType")
	if kind != "UserAuthenticate" && kind != "TokenUpdate" {
		return nil, ErrUnauthorized
	}
	// This service trusts user handles reported by the authenticated OS. It does
	// not accept a password digest or imply directory authentication.
	if _, present := message["DigestResponse"]; present {
		return nil, ErrUserChannelDeclined
	}
	short, err := validUserName(message, "UserShortName", 255)
	if err != nil {
		return nil, err
	}
	long, err := validUserName(message, "UserLongName", 512)
	if err != nil {
		return nil, err
	}
	notOnConsole := false
	if value, present := message["NotOnConsole"]; present {
		var ok bool
		notOnConsole, ok = value.(bool)
		if !ok {
			return nil, ErrUnauthorized
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	current, peer, err := s.lockUserParent(ctx, tx, d)
	if err != nil {
		return nil, err
	}
	if kind == "TokenUpdate" {
		if _, present := message["UserLongName"].(string); !present {
			return nil, ErrUnauthorized
		}
		if CompareVersions(current.OSVersion, "10.11") >= 0 {
			if _, present := message["NotOnConsole"].(bool); !present {
				return nil, ErrUnauthorized
			}
		}
		var topic string
		if err = tx.QueryRowContext(ctx, `SELECT topic FROM mdm_apple_settings WHERE tenant_id=$1`, current.TenantID).Scan(&topic); err != nil {
			return nil, err
		}
		if stringValue(message, "Topic") != topic {
			return nil, ErrUnauthorized
		}
	}
	// The parent lock serializes discovery, revocation, and every user write.
	u, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userColumns+` FROM mdm_apple_users WHERE device_id=$1 AND user_id=$2 FOR UPDATE`, current.ID, userID))
	if errors.Is(err, ErrNotFound) {
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_users WHERE device_id=$1`, current.ID).Scan(&count); err != nil {
			return nil, err
		}
		if count >= 1000 {
			return nil, ErrUserChannelDeclined
		}
		u = &UserChannel{ID: uuid.NewString(), DeviceID: current.ID, TenantID: current.TenantID, SiteID: current.SiteID, UserID: userID, Status: "pending"}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_users(id,tenant_id,site_id,device_id,user_id) VALUES($1,$2,$3,$4,$5)`, u.ID, u.TenantID, u.SiteID, u.DeviceID, u.UserID); err != nil {
			return nil, err
		}
		if err = audit(ctx, tx, u.TenantID, "device:"+current.ID, "apple.user.discover", u.ID); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if u.Status == "blocked" || u.Status == "not_managed" {
		return nil, ErrUserChannelDeclined
	}
	if kind == "UserAuthenticate" {
		data, err := plist.Marshal(map[string]any{"DigestChallenge": ""}, plist.XMLFormat)
		if err != nil {
			return nil, err
		}
		if _, err = s.deviceIdentityPeer(ctx, tx, d); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return data, nil
	}
	token, ok := message["Token"].([]byte)
	magic := stringValue(message, "PushMagic")
	if !ok || len(token) == 0 || len(token) > 512 || magic == "" || len(magic) > 1024 {
		return nil, ErrUnauthorized
	}
	if peer.kind == "candidate" {
		if err = s.stageUserIdentityToken(ctx, tx, current, u, peer.renewalID, token, magic, notOnConsole, short, long); err != nil {
			return nil, err
		}
	} else {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_users SET short_name=COALESCE(NULLIF($2,''),short_name),long_name=COALESCE(NULLIF($3,''),long_name),last_seen=clock_timestamp() WHERE id=$1`, u.ID, short, long); err != nil {
			return nil, err
		}
		if err = s.saveUserToken(ctx, tx, u, token, magic, notOnConsole); err != nil {
			return nil, err
		}
		if err = s.queueUserProfileInventory(ctx, tx, u); err != nil {
			return nil, err
		}
	}
	if err = audit(ctx, tx, u.TenantID, "device:"+current.ID, "apple.user.token", u.ID); err != nil {
		return nil, err
	}
	if _, err = s.deviceIdentityPeer(ctx, tx, d); err != nil {
		return nil, err
	}
	return nil, tx.Commit()
}

func (s *Store) saveUserToken(ctx context.Context, tx *sql.Tx, u *UserChannel, token []byte, magic string, notOnConsole bool) error {
	encrypted, err := s.secrets.seal(token, secretPurpose(u.TenantID, u.ID, "user_push_token"))
	if err != nil {
		return err
	}
	encryptedMagic, err := s.secrets.seal([]byte(magic), secretPurpose(u.TenantID, u.ID, "user_push_magic"))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_users SET push_token=$2,push_magic=$3,status='enrolled',not_on_console=$4,push_status='pending',push_error='',next_push_at=clock_timestamp(),last_seen=clock_timestamp() WHERE id=$1`, u.ID, encrypted, encryptedMagic, notOnConsole)
	return err
}

func (s *Store) Users(ctx context.Context, scope Scope, deviceID string) ([]UserChannel, error) {
	if _, err := s.Device(ctx, scope, deviceID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+userColumns+` FROM mdm_apple_users WHERE device_id=$1 AND tenant_id=$2 AND ($3=0 OR site_id=$3) ORDER BY short_name,user_id`, deviceID, scope.TenantID, scope.SiteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []UserChannel{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *u)
	}
	return result, rows.Err()
}

func (s *Store) User(ctx context.Context, scope Scope, deviceID, id string) (*UserChannel, error) {
	if _, err := s.Device(ctx, scope, deviceID); err != nil {
		return nil, err
	}
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM mdm_apple_users WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND ($4=0 OR site_id=$4)`, id, deviceID, scope.TenantID, scope.SiteID))
}

func (s *Store) withdrawUserChannels(ctx context.Context, tx *sql.Tx, d *Device) error {
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_users SET status='not_managed',push_token=NULL,push_magic=NULL,push_status='cancelled',push_error='' WHERE device_id=$1`, d.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_user_commands SET status='cancelled',payload=''::bytea,completed_at=clock_timestamp() WHERE device_id=$1 AND status IN ('queued','sent','not_now')`, d.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mdm_apple_user_renewal_tokens WHERE device_id=$1`, d.ID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_user_assignments SET status='not_managed',updated_at=clock_timestamp() WHERE device_id=$1`, d.ID)
	return err
}
