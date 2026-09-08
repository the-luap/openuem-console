// Package apple implements Apple's device management protocols natively in OpenUEM.
// It deliberately has no dependency on NanoMDM or a separate management server.
package apple

import (
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrNotFound     = errors.New("Apple management resource not found")
	ErrUnauthorized = errors.New("device identity is not authorized")
	ErrConflict     = errors.New("resource changed or is already in use")
)

type Scope struct{ TenantID, SiteID int }

func (s Scope) Validate() error {
	if s.TenantID <= 0 || s.SiteID < 0 {
		return errors.New("a valid organization and optional site are required")
	}
	return nil
}

type Settings struct {
	// AppleAccount is administrator metadata, never part of public device JSON.
	AppleAccount    string    `json:"-"`
	TenantID        int       `json:"tenant_id"`
	PublicURL       string    `json:"public_url"`
	Organization    string    `json:"organization"`
	Topic           string    `json:"topic"`
	PushExpiresAt   time.Time `json:"push_expires_at"`
	PushCertificate []byte    `json:"-"`
	PushKey         []byte    `json:"-"`
	CACertificate   []byte    `json:"-"`
	CAKey           []byte    `json:"-"`
}

type Device struct {
	ID                   string             `json:"id"`
	TenantID             int                `json:"tenant_id"`
	SiteID               int                `json:"site_id"`
	UDID                 string             `json:"udid"`
	Name                 string             `json:"name"`
	SerialNumber         string             `json:"serial_number"`
	Model                string             `json:"model"`
	OSVersion            string             `json:"os_version"`
	BuildVersion         string             `json:"build_version"`
	Supervised           bool               `json:"supervised"`
	Status               string             `json:"status"`
	LastSeen             *time.Time         `json:"last_seen"`
	InventoryAt          *time.Time         `json:"inventory_at"`
	AppsAt               *time.Time         `json:"apps_at"`
	ProfilesAt           *time.Time         `json:"profiles_at"`
	EnrolledAt           *time.Time         `json:"enrolled_at"`
	CertificateExpiresAt time.Time          `json:"certificate_expires_at"`
	Inventory            map[string]any     `json:"inventory"`
	Apps                 []Application      `json:"apps"`
	InstalledProfiles    []InstalledProfile `json:"installed_profiles"`
	DDMStatus            json.RawMessage    `json:"ddm_status"`
	PushStatus           string             `json:"push_status"`
	PushError            string             `json:"push_error"`
}

func (d Device) Platform() string {
	if len(d.Model) >= 4 && d.Model[:4] == "iPad" {
		return "iPadOS"
	}
	return "iOS"
}

func (d Device) InventoryFresh(now time.Time) bool {
	return d.InventoryAt != nil && now.Sub(*d.InventoryAt) <= 24*time.Hour
}

type Application struct {
	Identifier       string `plist:"Identifier" json:"identifier"`
	Name             string `plist:"Name" json:"name"`
	Version          string `plist:"Version" json:"version"`
	ShortVersion     string `plist:"ShortVersion" json:"short_version"`
	Installing       bool   `plist:"Installing" json:"installing"`
	AppStoreVendable bool   `plist:"AppStoreVendable" json:"app_store"`
	BundleSize       uint64 `plist:"BundleSize" json:"bundle_size"`
}

type InstalledProfile struct {
	Identifier string `plist:"PayloadIdentifier" json:"identifier"`
	UUID       string `plist:"PayloadUUID" json:"uuid"`
	Name       string `plist:"PayloadDisplayName" json:"name"`
	Version    uint64 `plist:"PayloadVersion" json:"version"`
	Managed    bool   `plist:"IsManaged" json:"managed"`
}

type Profile struct {
	ID           string    `json:"id"`
	TenantID     int       `json:"tenant_id"`
	Name         string    `json:"name"`
	Identifier   string    `json:"identifier"`
	UUID         string    `json:"uuid"`
	Revision     int       `json:"revision"`
	PayloadTypes []string  `json:"payload_types"`
	Payload      []byte    `json:"-"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Assignment struct {
	ProfileID string    `json:"profile_id"`
	DeviceID  string    `json:"device_id"`
	Name      string    `json:"name"`
	Revision  int       `json:"revision"`
	Desired   string    `json:"desired"`
	Status    string    `json:"status"`
	Error     string    `json:"error"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Command struct {
	ID          string     `json:"id"`
	DeviceID    string     `json:"device_id"`
	RequestType string     `json:"request_type"`
	Status      string     `json:"status"`
	Attempts    int        `json:"attempts"`
	Error       string     `json:"error"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at"`
	Payload     []byte     `json:"-"`
}

type UpdatePolicy struct {
	DeviceID      string    `json:"device_id"`
	TargetVersion string    `json:"target_version"`
	TargetBuild   string    `json:"target_build"`
	Deadline      string    `json:"deadline"` // Device-local yyyy-mm-ddThh:mm:ss, per Apple.
	DetailsURL    string    `json:"details_url"`
	Status        string    `json:"status"`
	Error         string    `json:"error"`
	UpdatedAt     time.Time `json:"updated_at"`
}
