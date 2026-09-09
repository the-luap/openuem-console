package apple

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"sort"
	"time"

	"github.com/open-uem/openuem-console/internal/mdm/ade"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type ADETarget struct {
	Serial, ProfileID, ProfileName, Status, ResponseStatus, RemoteProfileID, RemoteStatus string
	DeviceID, DeviceStatus, SetupState                                                    string
	Revision, Generation                                                                  int64
	AttemptedAt, ObservedAt                                                               *time.Time
	NextAttemptAt                                                                         time.Time
}

func (s *Store) ADETargets(ctx context.Context, tenant int, server, after string) ([]ADETarget, string, error) {
	if after != "" && !ade.ValidSerial(after) {
		return nil, "", ErrADEProfile
	}
	rows, err := s.db.QueryContext(ctx, `SELECT t.serial,COALESCE(t.profile_id::text,''),COALESCE(p.name,''),t.status,t.response_status,t.remote_profile_id,t.remote_status,t.revision,t.generation,t.attempted_at,t.observed_at,t.next_attempt_at,COALESCE(a.device_id::text,''),COALESCE(d.status,''),COALESCE(a.setup_state,'')
 FROM mdm_apple_ade_targets t LEFT JOIN mdm_apple_ade_profiles p ON p.id=t.profile_id AND p.tenant_id=t.tenant_id
 LEFT JOIN mdm_apple_ade_admissions a ON a.tenant_id=t.tenant_id AND a.server_id=t.server_id AND a.serial=t.serial AND a.generation=t.generation
 LEFT JOIN mdm_apple_devices d ON d.id=a.device_id AND d.tenant_id=a.tenant_id
 WHERE t.tenant_id=$1 AND t.server_id=$2 AND t.serial>$3 ORDER BY t.serial LIMIT 101`, tenant, server, after)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	list := []ADETarget{}
	for rows.Next() {
		var v ADETarget
		if err = rows.Scan(&v.Serial, &v.ProfileID, &v.ProfileName, &v.Status, &v.ResponseStatus, &v.RemoteProfileID, &v.RemoteStatus, &v.Revision, &v.Generation, &v.AttemptedAt, &v.ObservedAt, &v.NextAttemptAt, &v.DeviceID, &v.DeviceStatus, &v.SetupState); err != nil {
			return nil, "", err
		}
		if len(list) == 100 {
			return list, list[99].Serial, nil
		}
		list = append(list, v)
	}
	return list, "", rows.Err()
}

func adeTargetSerials(serials []string) ([]string, error) {
	if len(serials) == 0 || len(serials) > ade.PageLimit {
		return nil, ErrADEProfile
	}
	seen := make(map[string]bool, len(serials))
	for _, serial := range serials {
		if !ade.ValidSerial(serial) || seen[serial] {
			return nil, ErrADEProfile
		}
		seen[serial] = true
	}
	result := append([]string(nil), serials...)
	sort.Strings(result)
	return result, nil
}

func (s *Store) SetADETargets(ctx context.Context, tenant int, server, profile string, serials []string, actor string, permissions *access.Store) error {
	return s.setADETargets(ctx, tenant, server, profile, serials, actor, func(ctx context.Context, tx *sql.Tx) error {
		if err := adePermission(permissions, tenant, actor)(ctx, tx); err != nil {
			return err
		}
		if profile == "" {
			return nil
		}
		return adeAssignedProfilePermission(ctx, tx, permissions, tenant, server, profile, actor)
	})
}

func adeAssignedProfilePermission(ctx context.Context, tx *sql.Tx, permissions *access.Store, tenant int, server, profile, actor string) error {
	var site int
	var deviceLock bool
	// Scope and rights are immutable; the mutation separately locks and checks
	// the selected version's current publication state.
	if err := tx.QueryRowContext(ctx, `SELECT site_id,(device_lock_allowed OR admin_options IS NOT NULL) FROM mdm_apple_ade_profiles WHERE tenant_id=$1 AND server_id=$2 AND id=$3`, tenant, server, profile).Scan(&site, &deviceLock); err != nil {
		return notFound(err)
	}
	return adeEnrollmentPermission(permissions, tenant, site, actor, deviceLock)(ctx, tx)
}

// A blank profile requests removal at Apple's next activation. This does not
// remove an installed MDM profile, revoke an identity, or reset a device.
func (s *Store) setADETargets(ctx context.Context, tenant int, server, profile string, serials []string, actor string, authorize func(context.Context, *sql.Tx) error) error {
	serials, err := adeTargetSerials(serials)
	if err != nil {
		return err
	}
	ctx, stop := context.WithTimeout(ctx, 20*time.Second)
	defer stop()
	tx, err := s.adeTx(ctx, tenant, actor, authorize)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM mdm_apple_ade_servers WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, server).Scan(&state); err != nil {
		return notFound(err)
	}
	if state != "connected" {
		return ErrADEProfile
	}
	if profile != "" {
		if err = tx.QueryRowContext(ctx, `SELECT status FROM mdm_apple_ade_profiles WHERE tenant_id=$1 AND server_id=$2 AND id=$3 FOR SHARE`, tenant, server, profile).Scan(&state); err != nil {
			return notFound(err)
		}
		if state != "published" {
			return ErrADEProfile
		}
	}
	for _, serial := range serials {
		var assigned bool
		if err = tx.QueryRowContext(ctx, `SELECT assigned FROM mdm_apple_ade_devices WHERE tenant_id=$1 AND server_id=$2 AND serial=$3`, tenant, server, serial).Scan(&assigned); err != nil {
			return notFound(err)
		}
		if !assigned {
			return ErrADEProfile
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_ade_targets(tenant_id,server_id,serial,profile_id) VALUES($1,$2,$3,NULLIF($4,'')::uuid)
 ON CONFLICT(tenant_id,server_id,serial) DO UPDATE SET profile_id=excluded.profile_id,revision=mdm_apple_ade_targets.revision+1,status='pending',response_status='',
 next_attempt_at=GREATEST(clock_timestamp(),mdm_apple_ade_targets.retry_after),updated_at=clock_timestamp()`, tenant, server, serial, profile)
		if err != nil {
			return err
		}
		operation := "assign"
		if profile == "" {
			operation = "clear"
		}
		resource := server + "/" + serial + "/" + profile
		if profile == "" {
			resource += "clear"
		}
		if err = audit(ctx, tx, tenant, actor, "apple.ade.target."+operation, resource); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) RearmADETarget(ctx context.Context, tenant int, server, serial, actor string, permissions *access.Store) error {
	return s.rearmADETarget(ctx, tenant, server, serial, actor, func(ctx context.Context, tx *sql.Tx) error {
		if err := adePermission(permissions, tenant, actor)(ctx, tx); err != nil {
			return err
		}
		var profile string
		// The server lock prevents the target switching to a differently scoped
		// profile between authorization and re-arming.
		if _, err := tx.ExecContext(ctx, `SELECT id FROM mdm_apple_ade_servers WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, server); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(profile_id::text,'') FROM mdm_apple_ade_targets WHERE tenant_id=$1 AND server_id=$2 AND serial=$3`, tenant, server, serial).Scan(&profile); err != nil {
			return notFound(err)
		}
		if profile == "" {
			return ErrADEProfile
		}
		return adeAssignedProfilePermission(ctx, tx, permissions, tenant, server, profile, actor)
	})
}

func (s *Store) rearmADETarget(ctx context.Context, tenant int, server, serial, actor string, authorize func(context.Context, *sql.Tx) error) error {
	if !ade.ValidSerial(serial) {
		return ErrADEProfile
	}
	tx, err := s.adeTx(ctx, tenant, actor, authorize)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var connection string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM mdm_apple_ade_servers WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, server).Scan(&connection); err != nil {
		return notFound(err)
	}
	if connection != "connected" {
		return ErrADEProfile
	}
	var generation int64
	var profile string
	if err = tx.QueryRowContext(ctx, `SELECT generation,COALESCE(profile_id::text,'') FROM mdm_apple_ade_targets WHERE tenant_id=$1 AND server_id=$2 AND serial=$3 FOR UPDATE`, tenant, server, serial).Scan(&generation, &profile); err != nil {
		return notFound(err)
	}
	if profile == "" {
		return ErrADEProfile
	}
	var status string
	if err = tx.QueryRowContext(ctx, `SELECT d.status FROM mdm_apple_ade_admissions a JOIN mdm_apple_devices d ON d.id=a.device_id AND d.tenant_id=a.tenant_id WHERE a.tenant_id=$1 AND a.server_id=$2 AND a.serial=$3 AND a.generation=$4 FOR UPDATE OF d`, tenant, server, serial, generation).Scan(&status); err != nil {
		return notFound(err)
	}
	if status != "revoked" && status != "unenrolled" {
		return ErrADEProfile
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_targets SET generation=generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND server_id=$2 AND serial=$3`, tenant, server, serial); err != nil {
		return err
	}
	if err = audit(ctx, tx, tenant, actor, "apple.ade.target.rearm", server+"/"+serial); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) reconcileADETargetBatch(ctx context.Context, tenant int, server string) error {
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var connection string
	err = tx.QueryRowContext(ctx, `SELECT status FROM mdm_apple_ade_servers WHERE tenant_id=$1 AND id=$2 AND status='connected' AND (retry_after IS NULL OR retry_after<=clock_timestamp()) FOR UPDATE SKIP LOCKED`, tenant, server).Scan(&connection)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var profileID string
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(profile_id::text,'') FROM mdm_apple_ade_targets WHERE tenant_id=$1 AND server_id=$2 AND status<>'failed' AND next_attempt_at<=clock_timestamp() ORDER BY next_attempt_at,serial LIMIT 1`, tenant, server).Scan(&profileID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	remoteID := ""
	if profileID != "" {
		p, err := scanADEProfile(tx.QueryRowContext(ctx, `SELECT `+adeProfileColumns+` FROM mdm_apple_ade_profiles WHERE tenant_id=$1 AND server_id=$2 AND id=$3 FOR SHARE`, tenant, server, profileID))
		if err != nil {
			return err
		}
		if p.Status != "published" {
			return ErrADEProfile
		}
		remoteID = p.RemoteID
	}
	rows, err := tx.QueryContext(ctx, `SELECT serial FROM mdm_apple_ade_targets WHERE tenant_id=$1 AND server_id=$2 AND profile_id IS NOT DISTINCT FROM NULLIF($3,'')::uuid AND status<>'failed' AND next_attempt_at<=clock_timestamp() ORDER BY serial LIMIT 1000 FOR UPDATE`, tenant, server, profileID)
	if err != nil {
		return err
	}
	serials := []string{}
	for rows.Next() {
		var serial string
		if err = rows.Scan(&serial); err != nil {
			rows.Close()
			return err
		}
		serials = append(serials, serial)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(serials) == 0 {
		return nil
	}
	setState := func(serial, status, response, observedProfile, observedStatus string, at *time.Time, after time.Duration) error {
		_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_ade_targets SET status=$4,response_status=$5,remote_profile_id=$6,remote_status=$7,observed_at=$8,attempted_at=clock_timestamp(),next_attempt_at=GREATEST($9,retry_after),retry_after=CASE WHEN $4='throttled' THEN GREATEST($9,retry_after) ELSE retry_after END,updated_at=clock_timestamp() WHERE tenant_id=$1 AND server_id=$2 AND serial=$3`, tenant, server, serial, status, response, observedProfile, observedStatus, at, time.Now().Add(after))
		return err
	}
	fail := func(cause error) error {
		code, after := adeEnrollmentFailure(cause)
		if err := saveADERetry(ctx, tx, tenant, server, cause); err != nil {
			return err
		}
		for _, serial := range serials {
			if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_ade_targets SET status='unavailable',response_status=$4,attempted_at=clock_timestamp(),next_attempt_at=GREATEST($5,retry_after),updated_at=clock_timestamp() WHERE tenant_id=$1 AND server_id=$2 AND serial=$3`, tenant, server, serial, code, time.Now().Add(after)); err != nil {
				return err
			}
		}
		if err := auditOutcome(ctx, tx, tenant, "system", "apple.ade.targets.reconcile", server, "deferred"); err != nil {
			return err
		}
		return tx.Commit()
	}
	network, stop := context.WithTimeout(ctx, 15*time.Second)
	defer stop()
	client, err := s.openADEEnrollmentService(network, tx, tenant, server)
	if err != nil {
		return fail(err)
	}
	defer client.Close()
	details, err := client.DeviceDetails(network, serials)
	if err != nil {
		return fail(err)
	}
	apply := []string{}
	now := time.Now()
	for _, serial := range serials {
		d, found := details[serial]
		if !found || d.ResponseStatus != "SUCCESS" {
			status := d.ResponseStatus
			if !found {
				status = "NOT_RETURNED"
			}
			if err = setState(serial, "unavailable", status, "", "", &now, time.Hour); err != nil {
				return err
			}
			continue
		}
		if d.ProfileID == remoteID && (remoteID == "" || d.ProfileStatus == "assigned" || d.ProfileStatus == "pushed") {
			if err = setState(serial, "observed", "SUCCESS", d.ProfileID, d.ProfileStatus, &now, time.Hour); err != nil {
				return err
			}
			continue
		}
		apply = append(apply, serial)
	}
	if len(apply) > 0 {
		var result ade.AssignmentResult
		if profileID == "" {
			result, err = client.ClearProfile(network, apply)
		} else {
			result, err = client.AssignProfile(network, remoteID, apply)
		}
		stop()
		if err != nil {
			return fail(err)
		}
		for _, serial := range apply {
			response := result.Devices[serial]
			status, after := "failed", 24*time.Hour
			switch response {
			case "SUCCESS":
				status, after = "accepted", 15*time.Second
			case "THROTTLED":
				status, after = "throttled", max(time.Second, result.RetryAfter)
			}
			d := details[serial]
			if err = setState(serial, status, response, d.ProfileID, d.ProfileStatus, &now, after); err != nil {
				return err
			}
		}
	}
	if err = audit(ctx, tx, tenant, "system", "apple.ade.targets.reconcile", server); err != nil {
		return err
	}
	return tx.Commit()
}

// ReconcileADEEnrollments is independent of inventory pagination. Publication
// and assignment remain scheduled even during a long-running full fetch.
func (s *Store) ReconcileADEEnrollments(ctx context.Context) error {
	type item struct {
		tenant     int
		server, id string
	}
	rows, err := s.db.QueryContext(ctx, `SELECT p.tenant_id,p.server_id,p.id FROM mdm_apple_ade_profiles p JOIN mdm_apple_ade_servers s ON s.id=p.server_id AND s.tenant_id=p.tenant_id WHERE (p.status='publishing' AND p.attempted_at<clock_timestamp()-interval '2 minutes') OR (p.status='queued' AND p.next_attempt_at<=clock_timestamp() AND s.status='connected' AND (s.retry_after IS NULL OR s.retry_after<=clock_timestamp())) ORDER BY p.next_attempt_at,p.id LIMIT 1`)
	if err != nil {
		return err
	}
	profiles := []item{}
	for rows.Next() {
		var v item
		if err = rows.Scan(&v.tenant, &v.server, &v.id); err != nil {
			rows.Close()
			return err
		}
		profiles = append(profiles, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var publicationError error
	for _, p := range profiles {
		work, cancel := context.WithTimeout(ctx, 18*time.Second)
		publicationError = s.publishADEProfile(work, p.tenant, p.server, p.id)
		cancel()
	}
	rows, err = s.db.QueryContext(ctx, `SELECT s.tenant_id,s.id FROM mdm_apple_ade_servers s WHERE s.status='connected' AND (s.retry_after IS NULL OR s.retry_after<=clock_timestamp()) AND EXISTS(SELECT 1 FROM mdm_apple_ade_targets t WHERE t.tenant_id=s.tenant_id AND t.server_id=s.id AND t.status<>'failed' AND t.next_attempt_at<=clock_timestamp()) ORDER BY (SELECT min(t.next_attempt_at) FROM mdm_apple_ade_targets t WHERE t.tenant_id=s.tenant_id AND t.server_id=s.id AND t.status<>'failed'),s.id LIMIT 1`)
	if err != nil {
		return err
	}
	servers := []item{}
	for rows.Next() {
		var v item
		if err = rows.Scan(&v.tenant, &v.server); err != nil {
			rows.Close()
			return err
		}
		servers = append(servers, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, server := range servers {
		work, cancel := context.WithTimeout(ctx, 18*time.Second)
		err = s.reconcileADETargetBatch(work, server.tenant, server.server)
		cancel()
		if err != nil {
			return errors.Join(publicationError, err)
		}
	}
	return publicationError
}

func (s *Store) runADEEnrollments(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		work, cancel := context.WithTimeout(ctx, 40*time.Second)
		if err := s.ReconcileADEEnrollments(work); err != nil && ctx.Err() == nil {
			logger.Error("Apple automated enrollment reconciliation failed")
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
