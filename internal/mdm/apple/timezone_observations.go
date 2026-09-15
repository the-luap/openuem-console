package apple

import (
	"context"
	"database/sql"
	"errors"
)

// Apple's query schema introduces TimeZone in iOS 14 and macOS 26. Its macOS
// response schema remains inconsistent; absent responses never imply a zone.
func supportsTimeZoneQuery(d Device) bool {
	if !versionPattern.MatchString(d.OSVersion) {
		return false
	}
	switch d.Family() {
	case PlatformIOS, PlatformIPadOS:
		return CompareVersions(d.OSVersion, "14.0") >= 0
	case PlatformMacOS:
		return CompareVersions(d.OSVersion, "26.0") >= 0
	default:
		return false
	}
}

// Device Information is a fresh query response, not an incremental DDM status.
// Missing/invalid zone evidence clears the projection instead of preserving a
// merged older value. The caller retains the authenticated exclusive device lock.
func recordTimeZoneObservation(ctx context.Context, tx *sql.Tx, d *Device, value any) error {
	name, _ := value.(string)
	_, valid := reportedTimeZoneLocation(name)
	if !supportsTimeZoneQuery(*d) || !valid {
		_, err := tx.ExecContext(ctx, `DELETE FROM mdm_apple_timezone_observations WHERE device_id=$1`, d.ID)
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_apple_timezone_observations(device_id,name,source,recorded_at) VALUES($1,$2,'device_information',clock_timestamp()) ON CONFLICT(device_id) DO UPDATE SET name=excluded.name,source=excluded.source,recorded_at=excluded.recorded_at`, d.ID, name)
	return err
}

func currentTimeZoneObservation(ctx context.Context, tx *sql.Tx, id string) (*TimeZoneObservation, error) {
	zone := &TimeZoneObservation{}
	err := tx.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(name) BETWEEN 1 AND 128 THEN name ELSE NULL END,CASE WHEN source='device_information' THEN source ELSE NULL END,recorded_at FROM mdm_apple_timezone_observations WHERE device_id=$1`, id).Scan(&zone.Name, &zone.Source, &zone.RecordedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return zone, nil
}
