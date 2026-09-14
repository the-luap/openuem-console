package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func installationObservedReceipt(t *testing.T, c netbirdcommand.ControlRequest, status string) *netbirdcommand.ControlResponse {
	t.Helper()
	require.Equal(t, netbirdcommand.RecoveryVersion, c.Version)
	require.Equal(t, "receipt", c.Kind)
	response, err := netbirdcommand.ControlResponseFor(c, "ok")
	require.NoError(t, err)
	response.Receipt = netbirdcommand.Receipt{Version: 1, RequestID: c.ReferenceID, DeviceID: c.DeviceID, Revision: c.Revision, CommandHash: c.CommandHash, Operation: "install", Status: status}
	if status == "withdrawn" {
		response.ReleaseID = uuid.NewString()
	}
	return &response
}

func TestNetbirdInstallationObservationRecoversCompletionAfterRenewalAndRevocation(t *testing.T) {
	f, requests, packages, pkg := installationFixture(t, nil)
	r := installationRequest(t, f, requests, pkg)
	var calls, queries atomic.Int32
	var original netbirdcommand.Command
	s := installationDeliveryStore(t, f, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		if c.Kind != "receipt" {
			return installationCapabilities(ctx, c)
		}
		queries.Add(1)
		require.Equal(t, strings.Repeat("e", 64), c.CertificateHash)
		hash, err := original.Digest()
		require.NoError(t, err)
		require.Equal(t, hash, c.CommandHash)
		return installationObservedReceipt(t, c, "completed"), nil
	}, func(_ context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		calls.Add(1)
		original = c
		return nil, errors.New("owned lost installer response")
	})
	_, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	lost, err := s.Install(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, "unconfirmed", lost.Outcome)
	_, err = f.db.ExecContext(t.Context(), `UPDATE uem_agent_identities SET certificate_hash=repeat('e',64) WHERE id=$1`, f.id)
	require.NoError(t, err)
	_, err = packages.Revoke(t.Context(), "tag-admin", access.Scope{TenantID: f.scope.TenantID}, pkg.ApprovalID, r.ApprovalDigest, uuid.NewString())
	require.NoError(t, err)
	recovered, err := s.ObserveInstallation(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, "completed", recovered.Outcome)
	require.Equal(t, "completed", recovered.ObservedOutcome)
	require.NotNil(t, recovered.CompletedAt)
	require.Equal(t, "operator", recovered.ObservedBy)
	require.Equal(t, lost.RecordedAt, recovered.RecordedAt)
	require.Equal(t, "completed", recovered.Receipt.Status)
	var originalOutcome string
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT outcome FROM uem_netbird_installation_results WHERE request_id=$1`, r.ID).Scan(&originalOutcome))
	require.Equal(t, "unconfirmed", originalOutcome)
	repeat, err := s.ObserveInstallation(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, recovered, repeat)
	require.EqualValues(t, 1, calls.Load())
	require.EqualValues(t, 1, queries.Load())
	// Completion is immutable; the original cancellation API cannot rewrite it.
	_, err = requests.Cancel(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	for _, query := range []string{`UPDATE uem_netbird_installations SET completed_at=NULL`, `UPDATE uem_netbird_installation_attempts SET command_hash=repeat('f',64)`, `DELETE FROM uem_netbird_installation_results`, `DELETE FROM uem_netbird_installation_observations`} {
		_, err = f.db.ExecContext(t.Context(), query)
		require.Error(t, err)
	}
	data, err := json.Marshal(recovered)
	require.NoError(t, err)
	require.NotContains(t, string(data), "owned-installation-source")
	require.NotContains(t, string(data), "certificate_hash")
}

func TestNetbirdInstallationObservationKeepsUncertainBarrierAndRejectsForeignProof(t *testing.T) {
	for _, kind := range []string{"missing", "blocked", "unavailable", "unconfirmed", "withdrawn", "released", "wrong-hash", "wrong-certificate", "wrong-revision", "wrong-kind", "nil", "error", "audit"} {
		t.Run(kind, func(t *testing.T) {
			f, requests, _, pkg := installationFixture(t, nil)
			r := installationRequest(t, f, requests, pkg)
			s := installationDeliveryStore(t, f, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
				if c.Kind != "receipt" {
					return installationCapabilities(ctx, c)
				}
				response := installationObservedReceipt(t, c, "completed")
				switch kind {
				case "missing", "blocked", "unavailable":
					v, err := netbirdcommand.ControlResponseFor(c, kind)
					return &v, err
				case "unconfirmed", "withdrawn":
					response = installationObservedReceipt(t, c, kind)
				case "released":
					response = installationObservedReceipt(t, c, "unconfirmed")
					response.ReleaseID = uuid.NewString()
				case "wrong-hash":
					response.Receipt.CommandHash = strings.Repeat("f", 64)
				case "wrong-certificate":
					response.CertificateHash = strings.Repeat("f", 64)
				case "wrong-revision":
					response.Receipt.Revision = strings.Repeat("f", 64)
				case "wrong-kind":
					response.Kind = "release"
				case "nil":
					return nil, nil
				case "error":
					return nil, errors.New("owned private observer diagnostic")
				}
				return response, nil
			}, func(_ context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
				receipt, err := netbirdcommand.ReceiptFor(c, "unconfirmed")
				return &receipt, err
			})
			_, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
			require.NoError(t, err)
			_, err = s.Install(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
			require.NoError(t, err)
			if kind == "audit" {
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_install_observe_failure CHECK(action<>'inventory.netbird.resolution.observe') NOT VALID`)
				require.NoError(t, err)
			}
			observed, err := s.ObserveInstallation(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision)
			if kind == "audit" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, "unconfirmed", observed.Outcome)
				require.Nil(t, observed.CompletedAt)
			}
			_, err = requests.Cancel(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision, uuid.NewString())
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
			_, err = requests.Request(t.Context(), "tag-admin", f.scope, f.id, uuid.NewString(), pkg.ApprovalID, r.ApprovalDigest, r.Revision)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
			_, err = f.db.ExecContext(t.Context(), `UPDATE uem_netbird_installations SET completed_at=clock_timestamp() WHERE id=$1`, r.ID)
			require.Error(t, err)
		})
	}
}

func TestNetbirdInstallationObservationRecoversMissingResultAndRetainsScope(t *testing.T) {
	f, requests, _, pkg := installationFixture(t, nil)
	r := installationRequest(t, f, requests, pkg)
	var queries atomic.Int32
	s := installationDeliveryStore(t, f, func(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		if c.Kind != "receipt" {
			return installationCapabilities(ctx, c)
		}
		queries.Add(1)
		return installationObservedReceipt(t, c, "completed"), nil
	}, func(_ context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		_, err := f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_install_lost_result CHECK(resource_id NOT LIKE '%/install/result-%') NOT VALID`)
		require.NoError(t, err)
		result, err := netbirdcommand.ReceiptFor(c, "completed")
		return &result, err
	})
	_, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	_, err = s.Install(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.Error(t, err)
	_, err = s.ObserveInstallation(t.Context(), "viewer", f.scope, f.id, r.ID, r.Revision)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = s.ObserveInstallation(t.Context(), "admin", access.Scope{TenantID: f.scope.TenantID, SiteID: f.otherSite}, f.id, r.ID, r.Revision)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = s.ObserveInstallation(t.Context(), "operator", f.scope, f.id, r.ID, strings.Repeat("f", 64))
	require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
	require.Zero(t, queries.Load())
	recovered, err := s.ObserveInstallation(t.Context(), "operator", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	require.Equal(t, "completed", recovered.Outcome)
	require.Nil(t, recovered.RecordedAt)
	var results int
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_installation_results`).Scan(&results))
	require.Zero(t, results)
	require.NoError(t, inventory.Migrate(t.Context(), f.db))
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_installations DISABLE TRIGGER uem_netbird_installation_completion_valid`)
	require.NoError(t, err)
	require.Error(t, inventory.Migrate(t.Context(), f.db))
}

func TestNetbirdInstallationDatabaseRejectsForgedReceiptsAndObservations(t *testing.T) {
	f, requests, _, pkg := installationFixture(t, nil)
	r := installationRequest(t, f, requests, pkg)
	var command netbirdcommand.Command
	s := installationDeliveryStore(t, f, nil, func(_ context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		command = c
		_, err := f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_native_proof_failure CHECK(resource_id NOT LIKE '%/install/result-%') NOT VALID`)
		require.NoError(t, err)
		result, err := netbirdcommand.ReceiptFor(c, "completed")
		return &result, err
	})
	_, err := s.Prepare(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.NoError(t, err)
	_, err = s.Install(t.Context(), "tag-admin", f.scope, f.id, r.ID, r.Revision)
	require.Error(t, err)
	receipt, err := netbirdcommand.ReceiptFor(command, "completed")
	require.NoError(t, err)
	for _, change := range []string{"hash", "device", "status", "extra", "null"} {
		data, err := netbirdcommand.EncodeReceipt(receipt)
		require.NoError(t, err)
		var value map[string]any
		require.NoError(t, json.Unmarshal(data, &value))
		switch change {
		case "hash":
			value["command_hash"] = strings.Repeat("f", 64)
		case "device":
			value["device_id"] = uuid.NewString()
		case "status":
			value["status"] = "unconfirmed"
		case "extra":
			value["output"] = "owned private diagnostics"
		case "null":
			value = nil
		}
		data, err = json.Marshal(value)
		require.NoError(t, err)
		_, err = f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_installation_results(request_id,outcome,receipt) VALUES($1,'completed',$2::jsonb)`, r.ID, string(data))
		require.Error(t, err, change)
	}
	var count int
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_installation_results`).Scan(&count))
	require.Zero(t, count)
	for _, change := range []string{"hash", "extra", "identity", "release", "version", "reference", "missing-receipt"} {
		var at time.Time
		require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT clock_timestamp()`).Scan(&at))
		at = at.UTC()
		c := netbirdcommand.ControlRequest{Version: 2, Identity: command.Identity, RequestID: uuid.NewString(), Kind: "receipt", ReferenceID: r.ID, CommandHash: receipt.CommandHash, Revision: r.Revision, Operation: "install", IssuedAt: at, ExpiresAt: at.Add(time.Second)}
		response := installationObservedReceipt(t, c, "completed")
		control, err := netbirdcommand.EncodeControl(c)
		require.NoError(t, err)
		encoded, err := netbirdcommand.EncodeControlResponse(c, *response)
		require.NoError(t, err)
		var p, q map[string]any
		require.NoError(t, json.Unmarshal(encoded, &p))
		require.NoError(t, json.Unmarshal(control, &q))
		switch change {
		case "hash":
			p["request_hash"] = strings.Repeat("f", 64)
		case "extra":
			p["source"] = "https://owned.example.test/private"
		case "identity":
			p["certificate_hash"] = strings.Repeat("f", 64)
		case "release":
			p["release_id"] = uuid.NewString()
		case "version":
			q["version"] = 1
		case "reference":
			q["reference_id"] = uuid.NewString()
		case "missing-receipt":
			delete(p, "receipt")
		}
		control, err = json.Marshal(q)
		require.NoError(t, err)
		encoded, err = json.Marshal(p)
		require.NoError(t, err)
		hash, err := c.Digest()
		require.NoError(t, err)
		_, err = f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_installation_observations(id,request_id,actor,control_hash,control,response) VALUES($1,$2,'operator',$3,$4::jsonb,$5::jsonb)`, c.RequestID, r.ID, hash, string(control), string(encoded))
		require.Error(t, err, change)
	}
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_installation_observations`).Scan(&count))
	require.Zero(t, count)
	for _, guard := range [][2]string{{"uem_netbird_installation_attempts", "uem_netbird_installation_attempt_immutable"}, {"uem_netbird_installation_attempts", "uem_netbird_installation_attempt_valid"}, {"uem_netbird_installation_results", "uem_netbird_installation_result_immutable"}, {"uem_netbird_installation_results", "uem_netbird_installation_result_valid"}, {"uem_netbird_installation_observations", "uem_netbird_installation_observation_immutable"}, {"uem_netbird_installation_observations", "uem_netbird_installation_observation_valid"}} {
		_, err = f.db.ExecContext(t.Context(), "ALTER TABLE "+guard[0]+" DISABLE TRIGGER "+guard[1])
		require.NoError(t, err)
		require.Error(t, inventory.Migrate(t.Context(), f.db))
		_, err = f.db.ExecContext(t.Context(), "ALTER TABLE "+guard[0]+" ENABLE TRIGGER "+guard[1])
		require.NoError(t, err)
	}
	require.NoError(t, inventory.Migrate(t.Context(), f.db))
}
