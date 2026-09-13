package models

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/open-uem/ent"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/ent/netbird"
	"github.com/open-uem/nats"
	"github.com/open-uem/nats/legacysecret"
	"github.com/open-uem/nats/netbirdstate"
)

// HasNetbirdToken projects only a presence flag for inventory navigation.
func (m *Model) HasNetbirdToken(ctx context.Context, tenantID int) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if tenantID <= 0 {
		return false, errors.New("NetBird organization is unavailable")
	}
	var configured bool
	err := m.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tenants t JOIN netbird_settings n ON n.id=t.tenant_netbird WHERE t.id=$1 AND coalesce(n.access_token,'')<>'')`, tenantID).Scan(&configured)
	if err != nil {
		return false, errors.New("NetBird settings are unavailable")
	}
	return configured, nil
}

// GetNetbirdSettings is a bounded read. Missing configuration is never created
// while rendering inventory or preparing a provider operation.
func (m *Model) GetNetbirdSettings(parent context.Context, tenantID int) (*ent.NetbirdSettings, error) {
	if tenantID <= 0 {
		return nil, errors.New("NetBird organization is unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	result := &ent.NetbirdSettings{}
	var bounded bool
	err := m.DB.QueryRowContext(ctx, `SELECT n.id,coalesce(octet_length(n.management_url),0)<=2048 AND coalesce(octet_length(n.access_token),0)<=$2,
 CASE WHEN octet_length(n.management_url)<=2048 THEN n.management_url ELSE '' END,
 CASE WHEN octet_length(n.access_token)<=$2 THEN n.access_token ELSE '' END
 FROM netbird_settings n JOIN tenants t ON t.tenant_netbird=n.id WHERE t.id=$1`, tenantID, legacysecret.MaxStoredSize).Scan(&result.ID, &bounded, &result.ManagementURL, &result.AccessToken)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &ent.NotFoundError{}
	}
	if err != nil || !bounded {
		return nil, errors.New("NetBird settings are unavailable")
	}
	return result, nil
}

func (m *Model) SaveNetbirdInfo(agentID string, data nats.Netbird) error {
	if data.Error != "" {
		return errors.New("NetBird observation is unavailable")
	}
	profiles, err := netbirdstate.Encode(data)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return m.Client.Netbird.
		Create().
		SetVersion(data.Version).
		SetInstalled(data.Installed).
		SetIP(data.IP).
		SetSSHEnabled(data.SSHEnabled).
		SetProfile(data.Profile).
		SetManagementConnected(data.ManagementConnected).
		SetManagementURL(data.ManagementURL).
		SetSignalConnected(data.SignalConnected).
		SetSignalURL(data.SignalURL).
		SetPeersConnected(data.PeersConnected).
		SetPeersTotal(data.PeersTotal).
		SetServiceStatus(data.ServiceStatus).
		SetProfilesAvailable(profiles).
		SetDNSServer(strings.Join(data.DNSServers, ",")).
		SetOwnerID(agentID).
		OnConflictColumns(netbird.OwnerColumn).
		UpdateNewValues().
		Exec(ctx)
}

func (m *Model) SetNetbirdAsUninstalled(agentID string) error {
	return m.Client.Netbird.Update().SetInstalled(false).Where(netbird.HasOwnerWith(agent.ID(agentID))).Exec(context.Background())
}
