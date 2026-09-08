package apple

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	db                  *sql.DB
	secrets             *secretBox
	vendor              *VendorTrust
	pushTrust           *pushCertificateTrust
	checkPushConnection func(context.Context, *Settings) error
}

func NewStore(db *sql.DB, masterKey string) (*Store, error) {
	return NewStoreWithVendor(db, masterKey, nil)
}

// NewStoreWithVendor fixes the operator's vendor trust for this store's lifetime.
// Restart all replicas with the same explicit pins when changing vendors.
func NewStoreWithVendor(db *sql.DB, masterKey string, vendor *VendorTrust) (*Store, error) {
	if db == nil {
		return nil, errors.New("Apple management requires PostgreSQL")
	}
	box, err := newSecretBox(masterKey)
	if err != nil {
		return nil, err
	}
	if vendor != nil && (vendor.root == nil || len(vendor.pins) == 0) {
		return nil, ErrVendorNotConfigured
	}
	pushTrust, err := newPushCertificateTrust()
	if err != nil {
		return nil, err
	}
	return &Store{db: db, secrets: box, vendor: vendor, pushTrust: pushTrust, checkPushConnection: checkAPNsConnection}, nil
}

// Migrate is additive and serialized across console replicas. It never runs
// destructive upstream automatic schema synchronization.
func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627901)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS mdm_apple_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		var applied bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_migrations WHERE name=$1)`, name).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, string(body)); err != nil {
			return fmt.Errorf("Apple migration %s: %w", name, err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_migrations(name) VALUES($1)`, name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func secretPurpose(tenant int, resource, field string) string {
	return fmt.Sprintf("%d/%s/%s", tenant, resource, field)
}

func (s *Store) Settings(ctx context.Context, tenant int) (*Settings, error) {
	var c Settings
	err := s.db.QueryRowContext(ctx, `SELECT tenant_id,public_url,organization,topic,push_expires_at,push_certificate,push_key,ca_certificate,ca_key FROM mdm_apple_settings WHERE tenant_id=$1`, tenant).Scan(&c.TenantID, &c.PublicURL, &c.Organization, &c.Topic, &c.PushExpiresAt, &c.PushCertificate, &c.PushKey, &c.CACertificate, &c.CAKey)
	if err != nil {
		return nil, notFound(err)
	}
	c.PushKey, err = s.secrets.open(c.PushKey, secretPurpose(tenant, "settings", "push_key"))
	if err != nil {
		return nil, err
	}
	c.CAKey, err = s.secrets.open(c.CAKey, secretPurpose(tenant, "settings", "ca_key"))
	if err != nil {
		return nil, err
	}
	return &c, nil
}

const deviceColumns = `device_lock_allowed,per_user_connections,id,tenant_id,site_id,COALESCE(udid,''),name,serial_number,model,os_version,build_version,supervised,status,last_seen,inventory_at,apps_at,profiles_at,enrolled_at,certificate_expires_at,inventory,apps,installed_profiles,ddm_status,push_status,push_error,identity_renewal_error,platform,enrollment_method,supervised_reported,software_update_device_id,apple_silicon,security_inventory,security_at,enrollment_platform,EXISTS(SELECT 1 FROM mdm_apple_bootstrap_tokens b WHERE b.device_id=mdm_apple_devices.id AND b.tenant_id=mdm_apple_devices.tenant_id)`

type scanner interface{ Scan(...any) error }

func scanDevice(row scanner) (*Device, error) {
	var d Device
	var inventory, apps, profiles, security []byte
	err := row.Scan(&d.DeviceLockAllowed, &d.PerUserConnections, &d.ID, &d.TenantID, &d.SiteID, &d.UDID, &d.Name, &d.SerialNumber, &d.Model, &d.OSVersion, &d.BuildVersion, &d.Supervised, &d.Status, &d.LastSeen, &d.InventoryAt, &d.AppsAt, &d.ProfilesAt, &d.EnrolledAt, &d.CertificateExpiresAt, &inventory, &apps, &profiles, &d.DDMStatus, &d.PushStatus, &d.PushError, &d.IdentityRenewalError, &d.OSFamily, &d.EnrollmentMethod, &d.SupervisedReported, &d.SoftwareUpdateDeviceID, &d.AppleSilicon, &security, &d.SecurityAt, &d.EnrollmentPlatform, &d.BootstrapTokenEscrowed)
	if err != nil {
		return nil, notFound(err)
	}
	if err = json.Unmarshal(inventory, &d.Inventory); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(apps, &d.Apps); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(profiles, &d.InstalledProfiles); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(security, &d.SecurityInventory); err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) Device(ctx context.Context, scope Scope, id string) (*Device, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	return scanDevice(s.db.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE tenant_id=$1 AND ($2=0 OR site_id=$2) AND id=$3`, scope.TenantID, scope.SiteID, id))
}

func (s *Store) Devices(ctx context.Context, scope Scope) ([]Device, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE tenant_id=$1 AND ($2=0 OR site_id=$2) ORDER BY name,id`, scope.TenantID, scope.SiteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices := []Device{}
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, *d)
	}
	return devices, rows.Err()
}

func audit(ctx context.Context, tx *sql.Tx, tenant int, actor, action, resource string) error {
	return auditOutcome(ctx, tx, tenant, actor, action, resource, "success")
}
