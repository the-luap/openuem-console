package apple

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

type PushError struct {
	Status int
	Reason string
}

func (e *PushError) Error() string { return fmt.Sprintf("APNs %d: %s", e.Status, e.Reason) }

// APNs merely wakes a device. Acceptance here is recorded separately from the
// eventual MDM command acknowledgement and verified inventory state.
func Push(ctx context.Context, client *http.Client, endpoint, topic string, token []byte, magic string) error {
	body, err := json.Marshal(map[string]string{"mdm": magic})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/3/device/"+hex.EncodeToString(token), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("apns-topic", topic)
	req.Header.Set("apns-push-type", "mdm")
	req.Header.Set("apns-priority", "10")
	req.Header.Set("apns-expiration", "0")
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		return nil
	}
	var failure struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(io.LimitReader(res.Body, 8192)).Decode(&failure)
	return &PushError{Status: res.StatusCode, Reason: failure.Reason}
}

func pushClient(c *Settings) (*http.Client, error) {
	cert, err := tls.X509KeyPair(c.PushCertificate, c.PushKey)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, ForceAttemptHTTP2: true}
	return &http.Client{Transport: transport, Timeout: 20 * time.Second}, nil
}

// PushPending claims bounded work with PostgreSQL row locks. A replica crash
// releases work after its lease, and a server restart does not lose pending pushes.
func (s *Store) PushPending(ctx context.Context) error {
	for i := 0; i < 25; i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		var id string
		var tenant int
		var token, magic []byte
		err = tx.QueryRowContext(ctx, `SELECT id,tenant_id,push_token,push_magic FROM mdm_apple_devices d WHERE status='enrolled' AND push_token IS NOT NULL AND next_push_at<=now() AND EXISTS(SELECT 1 FROM mdm_apple_commands c WHERE c.device_id=d.id AND c.status IN ('queued','sent','not_now') AND c.expires_at>now() AND c.available_at<=now()) ORDER BY next_push_at LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&id, &tenant, &token, &magic)
		if errors.Is(err, sql.ErrNoRows) {
			tx.Rollback()
			return nil
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET next_push_at=now()+interval '5 minutes' WHERE id=$1`, id); err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		encryptedToken, encryptedMagic := token, magic
		c, err := s.Settings(ctx, tenant)
		if err == nil {
			token, err = s.secrets.open(token, secretPurpose(tenant, id, "push_token"))
		}
		if err == nil {
			magic, err = s.secrets.open(magic, secretPurpose(tenant, id, "push_magic"))
		}
		if err == nil {
			var client *http.Client
			client, err = pushClient(c)
			if err == nil {
				err = Push(ctx, client, "https://"+apnsProductionHost, c.Topic, token, string(magic))
				client.CloseIdleConnections()
			}
		}
		status, detail := "accepted", ""
		if err != nil {
			status = "failed"
			detail = err.Error()
		}
		var pushErr *PushError
		if errors.As(err, &pushErr) && (pushErr.Status == 410 || pushErr.Reason == "BadDeviceToken" || pushErr.Reason == "DeviceTokenNotForTopic") {
			status = "invalid_token"
		}
		if err = s.recordPushOutcome(ctx, id, encryptedToken, encryptedMagic, status, detail); err != nil {
			return err
		}
	}
	return nil
}

// Network requests outlive the device row lock. A response for an earlier token
// must not overwrite a later TokenUpdate, identity promotion, or revocation.
func (s *Store) recordPushOutcome(ctx context.Context, id string, token, magic []byte, status, detail string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE mdm_apple_devices SET push_status=$1,push_error=$2,next_push_at=CASE WHEN $1='invalid_token' THEN now()+interval '1 day' ELSE next_push_at END WHERE id=$3 AND status='enrolled' AND push_token=$4 AND push_magic=$5`, status, detail, id, token, magic)
	return err
}

func (s *Store) Run(ctx context.Context, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	adeDone := make(chan struct{})
	go func() { defer close(adeDone); s.runADEServers(ctx, logger) }()
	defer func() { <-adeDone }()
	adeEnrollmentDone := make(chan struct{})
	go func() { defer close(adeEnrollmentDone); s.runADEEnrollments(ctx, logger) }()
	defer func() { <-adeEnrollmentDone }()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		work, cancel := context.WithTimeout(ctx, 45*time.Second)
		if err := s.RefreshCatalog(work); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("Apple software catalog refresh failed", "error", err)
		}
		for _, task := range []func(context.Context) error{s.CleanupEnrollmentClaims, s.CleanupSCEPEnrollments, s.CleanupPushRequests, s.expireCommands, s.ReconcileMacApps, s.ReconcileMacAdmins, s.ReconcileADESetups, s.ReconcileRecoveryLocks, s.ReconcileMacBindings, s.ReconcileMacLinks, s.ReconcileFileVaultRotations, s.ReconcileFileVaultValidations, s.ReconcileFileVaultHistory, s.ReconcileIdentityRenewals, s.ScheduleIdentityRenewals, s.ScheduleInventory, s.MaintainUserChannels, s.ReconcileUpdateAvailability} {
			if err := task(work); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("Apple management maintenance failed", "error", err)
			}
		}
		if err := s.PushPending(work); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("Apple MDM push sweep failed", "error", err)
		}
		if err := s.PushUserPending(work); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("Apple user-channel push sweep failed", "error", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
