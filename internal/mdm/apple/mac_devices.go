package apple

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/open-uem/nats/enrollment"
)

// MacDevice is the stable, scoped identity and safe metadata for both channels.
type MacDevice struct {
	ID, MDMID, AgentID                string
	Name, Model, Serial, OSVersion    string
	MDMStatus, AgentStatus, AgentName string
	LastSeen, AgentSeen               *time.Time
	AgentExpiresAt                    time.Time
	History                           []MacChannelHistory
}
type MacChannelHistory struct {
	Kind, DeviceID, Status string
	AttachedAt             time.Time
	RetiredAt              *time.Time
}

func (s *Store) MacDevices(ctx context.Context, scope Scope) ([]MacDevice, error) {
	return s.macDevices(ctx, scope, "")
}

func (s *Store) macDevices(ctx context.Context, scope Scope, id string) ([]MacDevice, error) {
	if scope.Validate() != nil {
		return nil, ErrNotFound
	}
	if !s.MacLinksReady(ctx) {
		return []MacDevice{}, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT m.id,d.id,i.id,COALESCE(NULLIF(d.name,''),i.display_name),m.model,m.serial,d.os_version,CASE WHEN d.status='enrolled' AND d.certificate_expires_at<=clock_timestamp() THEN 'expired' ELSE d.status END,i.display_name,d.last_seen,h.observed_at,i.certificate_expires_at,
 CASE WHEN i.revoked_at IS NOT NULL THEN 'revoked' WHEN i.certificate_expires_at<=clock_timestamp() THEN 'expired'
 WHEN h.device_id IS NULL THEN 'unknown' WHEN h.model<>m.model OR h.serial<>m.serial OR h.platform_uuid<>m.platform_uuid OR h.provisioning_udid<>m.provisioning_udid THEN 'conflict'
 WHEN h.observed_at<clock_timestamp()-interval '24 hours' THEN 'stale' ELSE 'enrolled' END
 FROM uem_mac_devices m
 JOIN sites s ON s.id=m.site_id AND s.tenant_sites=m.tenant_id
 JOIN uem_mac_mdm_channels mc ON mc.entity_id=m.id AND mc.retired_at IS NULL
 JOIN mdm_apple_devices d ON d.id=mc.device_id AND d.tenant_id=m.tenant_id AND d.site_id=m.site_id
 JOIN uem_mac_agent_channels ac ON ac.entity_id=m.id AND ac.retired_at IS NULL
 JOIN uem_agent_identities i ON i.id=ac.device_id AND i.tenant_id=m.tenant_id AND i.site_id=m.site_id
 LEFT JOIN uem_agent_hardware h ON h.device_id=i.id
 WHERE m.tenant_id=$1 AND ($2=0 OR m.site_id=$2) AND ($3='' OR m.id=NULLIF($3,'')::uuid) ORDER BY m.created_at,m.id`, scope.TenantID, scope.SiteID, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []MacDevice{}
	for rows.Next() {
		var d MacDevice
		if err = rows.Scan(&d.ID, &d.MDMID, &d.AgentID, &d.Name, &d.Model, &d.Serial, &d.OSVersion, &d.MDMStatus, &d.AgentName, &d.LastSeen, &d.AgentSeen, &d.AgentExpiresAt, &d.AgentStatus); err != nil {
			return nil, err
		}
		list = append(list, d)
	}
	return list, rows.Err()
}

func (s *Store) MacDevice(ctx context.Context, scope Scope, id string) (*MacDevice, error) {
	if !enrollment.ValidDeviceID(id) {
		return nil, ErrNotFound
	}
	list, err := s.macDevices(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	var result *MacDevice
	for i := range list {
		if list[i].ID == id {
			result = &list[i]
			break
		}
	}
	if result == nil {
		return nil, ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT 'mdm',c.device_id,d.status,c.attached_at,c.retired_at FROM uem_mac_mdm_channels c JOIN mdm_apple_devices d ON d.id=c.device_id WHERE c.entity_id=$1 AND c.tenant_id=$2 AND ($3=0 OR c.site_id=$3)
 UNION ALL SELECT 'agent',c.device_id,CASE WHEN i.revoked_at IS NOT NULL THEN 'revoked' WHEN i.certificate_expires_at<=clock_timestamp() THEN 'expired' ELSE 'enrolled' END,c.attached_at,c.retired_at FROM uem_mac_agent_channels c JOIN uem_agent_identities i ON i.id=c.device_id WHERE c.entity_id=$1 AND c.tenant_id=$2 AND ($3=0 OR c.site_id=$3) ORDER BY 4 DESC,1,2`, id, scope.TenantID, scope.SiteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var h MacChannelHistory
		if err = rows.Scan(&h.Kind, &h.DeviceID, &h.Status, &h.AttachedAt, &h.RetiredAt); err != nil {
			return nil, err
		}
		result.History = append(result.History, h)
	}
	return result, rows.Err()
}

// MacAliases only groups list rows inside the requested scope. Historical source
// IDs retain a canonical read location; mutation routes keep their original ID.
func (s *Store) MacAliases(ctx context.Context, scope Scope) (map[string]string, map[string]string, error) {
	mdm, agent := map[string]string{}, map[string]string{}
	if scope.Validate() != nil {
		return nil, nil, ErrNotFound
	}
	if !s.MacLinksReady(ctx) {
		return mdm, agent, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT 'mdm',c.device_id,c.entity_id FROM uem_mac_mdm_channels c JOIN sites s ON s.id=c.site_id AND s.tenant_sites=c.tenant_id WHERE c.tenant_id=$1 AND ($2=0 OR c.site_id=$2)
 UNION ALL SELECT 'agent',c.device_id,c.entity_id FROM uem_mac_agent_channels c JOIN sites s ON s.id=c.site_id AND s.tenant_sites=c.tenant_id WHERE c.tenant_id=$1 AND ($2=0 OR c.site_id=$2)`, scope.TenantID, scope.SiteID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, id, entity string
		if err = rows.Scan(&kind, &id, &entity); err != nil {
			return nil, nil, err
		}
		if kind == "mdm" {
			mdm[id] = entity
		} else {
			agent[id] = entity
		}
	}
	return mdm, agent, rows.Err()
}

func (s *Store) MacForMDM(ctx context.Context, scope Scope, id string) (string, error) {
	if scope.Validate() != nil {
		return "", ErrNotFound
	}
	if !s.MacLinksReady(ctx) {
		return "", nil
	}
	var entity string
	err := s.db.QueryRowContext(ctx, `SELECT c.entity_id FROM uem_mac_mdm_channels c JOIN sites s ON s.id=c.site_id AND s.tenant_sites=c.tenant_id WHERE c.device_id=$1 AND c.tenant_id=$2 AND ($3=0 OR c.site_id=$3)`, id, scope.TenantID, scope.SiteID).Scan(&entity)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return entity, err
}
