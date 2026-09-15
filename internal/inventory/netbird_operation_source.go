package inventory

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	nats "github.com/open-uem/nats"
	"github.com/open-uem/nats/netbirdapi"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/nats/netbirdstate"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type NetbirdOperationReview struct {
	Target                                                   ManualTarget
	Operation, Profile, ProfileName, ManagementURL, Revision string
	identityExpiresAt                                        time.Time
	identity                                                 netbirdcommand.Identity
	Journal                                                  netbirdcommand.State
}

func netbirdOperationInput(operation, profile string) bool {
	switch operation {
	case "up", "down":
		return profile == ""
	case "switchprofile":
		return netbirdstate.ValidText(profile)
	default:
		return false
	}
}

func (s *NetbirdOperationStore) recordTx(ctx context.Context, actor string, scope access.Scope, capability access.Capability) (*sql.Tx, error) {
	if scope.TenantID <= 0 || scope.SiteID <= 0 {
		return nil, ErrNetbirdOperationInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if err = s.permissions.AuthorizeTransaction(ctx, tx, actor, capability, scope); err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func (s *NetbirdOperationStore) source(ctx context.Context, tx *sql.Tx, scope access.Scope, device, operation, profile string) (*NetbirdOperationReview, error) {
	if !netbirdOperationInput(operation, profile) {
		return nil, ErrNetbirdOperationInvalid
	}
	return s.operationSource(ctx, tx, scope, device, operation, profile)
}

// Registration supplies its own explicit registration-state inspector. Public
// connection methods continue to reject registration and never read a token.
func (s *NetbirdOperationStore) operationSource(ctx context.Context, tx *sql.Tx, scope access.Scope, device, operation, profile string) (*NetbirdOperationReview, error) {
	if (!netbirdOperationInput(operation, profile) && (operation != "register" || profile != "")) || scope.SiteID <= 0 {
		return nil, ErrNetbirdOperationInvalid
	}
	manual := &ManualExecutionStore{db: s.db, permissions: s.permissions, individual: s.individual}
	target, err := manual.target(ctx, tx, scope, device)
	if err != nil {
		return nil, err
	}
	r := &NetbirdOperationReview{Target: target, Operation: operation, Profile: profile}
	// Report writers lock their row before changing the installation generation.
	// Follow that order to avoid holding the generation while waiting on a writer.
	var raw string
	err = tx.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(profiles_available)<=$2 THEN profiles_available ELSE '' END FROM netbirds WHERE agent_netbird=$1 AND installed FOR SHARE`, device, netbirdstate.MaxStored).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNetbirdOperationChanged
	}
	if err != nil {
		return nil, err
	}
	var generation, link, provider, certificate, broker string
	var settingsID int64
	var consumerRevision int64
	err = tx.QueryRowContext(ctx, `SELECT b.revision::text,t.uem_netbird_revision::text,n.uem_netbird_revision::text,n.id,
 CASE WHEN octet_length(n.management_url)<=2048 THEN n.management_url ELSE '' END
 FROM uem_netbird_device_bindings b JOIN tenants t ON t.id=$2 JOIN netbird_settings n ON n.id=t.tenant_netbird
 WHERE b.device_id=$1 FOR SHARE OF b,t,n`, device, scope.TenantID).Scan(&generation, &link, &provider, &settingsID, &r.ManagementURL)
	if errors.Is(err, sql.ErrNoRows) || err == nil && !netbirdapi.ValidBase(r.ManagementURL) {
		return nil, ErrNetbirdOperationChanged
	}
	if err != nil {
		return nil, err
	}
	if s.individual {
		err = tx.QueryRowContext(ctx, `SELECT i.certificate_hash,i.broker_key,q.revision,i.certificate_expires_at FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id WHERE i.id=$1 AND i.tenant_id=$2 AND i.site_id=$3 FOR SHARE OF i,q`, device, scope.TenantID, scope.SiteID).Scan(&certificate, &broker, &consumerRevision, &r.identityExpiresAt)
		if err != nil {
			return nil, err
		}
		if len(certificate) != 64 || len(broker) > 256 {
			return nil, ErrNetbirdOperationChanged
		}
	}
	r.identity = netbirdcommand.Identity{DeviceID: device, TenantID: int64(scope.TenantID), SiteID: int64(scope.SiteID), Individual: s.individual, CertificateHash: certificate}
	if !r.identity.Valid() {
		return nil, ErrNetbirdOperationChanged
	}
	var selected nats.NetbirdProfile
	if operation == "switchprofile" {
		profiles, err := netbirdstate.Decode(raw)
		if err != nil {
			return nil, ErrNetbirdOperationChanged
		}
		found := false
		for _, entry := range profiles {
			if entry.Handle() == profile {
				selected = entry
				selected.Active = false
				r.ProfileName = entry.Name
				found = true
			}
		}
		if !found {
			return nil, ErrNetbirdOperationChanged
		}
	}
	if s.inspect == nil {
		return nil, ErrNetbirdOperationNotReady
	}
	deadline := time.Now().Add(2 * time.Second)
	if !r.identityExpiresAt.IsZero() && r.identityExpiresAt.Before(deadline) {
		deadline = r.identityExpiresAt
	}
	probe, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	r.Journal, err = s.inspect(probe, r.identity)
	if err != nil || probe.Err() != nil || !r.Journal.Valid() || r.Journal.Status != "ready" {
		return nil, ErrNetbirdOperationNotReady
	}
	data, err := json.Marshal(struct {
		Device, Generation, Link, Provider, Certificate, Broker, Operation string
		Scope                                                              access.Scope
		SettingsID                                                         int64
		ConsumerRevision                                                   int64
		Profile                                                            nats.NetbirdProfile
		JournalRevision                                                    string
	}{device, generation, link, provider, certificate, broker, operation, scope, settingsID, consumerRevision, selected, r.Journal.Revision})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	r.Revision = hex.EncodeToString(digest[:])
	return r, nil
}
