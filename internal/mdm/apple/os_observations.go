package apple

import (
	"context"
	"database/sql"
)

// recordOSObservation runs inside the authenticated protocol transaction with
// its exclusive native device lock. It does not borrow a build from an older
// packet or refresh a version timestamp from an unrelated incremental report.
func recordOSObservation(ctx context.Context, tx *sql.Tx, id, source string, version any, hasVersion bool, build any, hasBuild bool) error {
	if !hasVersion {
		if !hasBuild {
			return nil
		}
		// A build-only delta cannot prove its association with the last version.
		// Preserve the old version/time, but stop using its old build as evidence.
		_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_os_observations SET build='' WHERE device_id=$1`, id)
		return err
	}
	v, _ := version.(string)
	if len(v) > 32 || !versionPattern.MatchString(v) {
		_, err := tx.ExecContext(ctx, `DELETE FROM mdm_apple_os_observations WHERE device_id=$1`, id)
		return err
	}
	b, _ := build.(string)
	if !hasBuild || !updatePlanBuild.MatchString(b) {
		b = ""
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_apple_os_observations(device_id,version,build,source,recorded_at) VALUES($1,$2,$3,$4,clock_timestamp()) ON CONFLICT(device_id) DO UPDATE SET version=excluded.version,build=excluded.build,source=excluded.source,recorded_at=excluded.recorded_at`, id, v, b, source)
	return err
}

func recordDDMOSObservation(ctx context.Context, tx *sql.Tx, id string, report *StatusReport) error {
	// The generic parser retains arbitrary status errors. Until an error-free OS
	// observation arrives, do not claim that these fields are verified for a cohort.
	if len(report.Errors) > 0 {
		return recordOSObservation(ctx, tx, id, "declarative_status", nil, true, nil, false)
	}
	device, exists := report.StatusItems["device"]
	if !exists && !report.FullReport {
		return nil
	}
	deviceFields, ok := device.(map[string]any)
	if !ok {
		return recordOSObservation(ctx, tx, id, "declarative_status", nil, true, nil, false)
	}
	os, exists := deviceFields["operating-system"]
	if !exists && !report.FullReport {
		return nil
	}
	fields, ok := os.(map[string]any)
	if !ok {
		return recordOSObservation(ctx, tx, id, "declarative_status", nil, true, nil, false)
	}
	version, hasVersion := fields["version"]
	build, hasBuild := fields["build-version"]
	return recordOSObservation(ctx, tx, id, "declarative_status", version, hasVersion || report.FullReport, build, hasBuild)
}
