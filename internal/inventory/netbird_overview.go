package inventory

import (
	"context"
	"database/sql"
	"errors"
	"time"

	nats "github.com/open-uem/nats"
	"github.com/open-uem/nats/netbirdstate"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type NetbirdOverview struct {
	Target                                             ManualTarget
	Installed, ManagementConnected, SignalConnected    bool
	Version, ServiceStatus, Profile, ManagementURL, IP string
	Profiles                                           []nats.NetbirdProfile
	LastContact                                        *time.Time
}

// Overview reads reported state in one authorized membership snapshot. It makes
// no device/provider requests and reads no provider credentials or setup keys.
func (s *NetbirdOperationStore) Overview(parent context.Context, actor string, scope access.Scope, device string) (*NetbirdOverview, error) {
	if !ValidReportDeviceID(device) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.recordTx(ctx, actor, scope, access.ReadDevices)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r := &NetbirdOverview{Target: ManualTarget{ID: device, Scope: scope}}
	var profiles string
	var contact sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT coalesce(left(nullif(a.nickname,''),256),left(a.hostname,256),''),coalesce(a.os,''),a.last_contact,
 coalesce(n.installed,false),coalesce(n.management_connected,false),coalesce(n.signal_connected,false),
 coalesce(left(n.version,256),''),coalesce(left(n.service_status,256),''),coalesce(left(n.profile,256),''),coalesce(left(n.management_url,2048),''),coalesce(left(n.ip,256),''),
 CASE WHEN octet_length(n.profiles_available)<=$5 THEN coalesce(n.profiles_available,'') ELSE '' END
 FROM agents a JOIN site_agents sa ON sa.agent_id=a.oid JOIN sites si ON si.id=sa.site_id LEFT JOIN netbirds n ON n.agent_netbird=a.oid
 WHERE a.oid=$1 AND si.tenant_sites=$2 AND si.id=$3 AND a.agent_status<>$4 AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1`, device, scope.TenantID, scope.SiteID, "WaitingForAdmission", netbirdstate.MaxStored).Scan(&r.Target.Name, &r.Target.Platform, &contact, &r.Installed, &r.ManagementConnected, &r.SignalConnected, &r.Version, &r.ServiceStatus, &r.Profile, &r.ManagementURL, &r.IP, &profiles)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if contact.Valid {
		r.LastContact = &contact.Time
	}
	if r.Target.Platform == "macOS" {
		r.Target.Platform = "macos"
	}
	if r.Target.Platform != "windows" && r.Target.Platform != "linux" && r.Target.Platform != "macos" {
		return nil, ErrManualUnsupported
	}
	if profiles != "" {
		r.Profiles, _ = netbirdstate.Decode(profiles)
	}
	if err = netbirdOperationAudit(ctx, tx, &NetbirdOperation{DeviceID: device, Scope: scope, Operation: "state"}, actor, "read", "recorded"); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}
