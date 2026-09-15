package inventory

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/exporttext"
)

var (
	ErrDeviceExportTooLarge = errors.New("device export exceeds supported bounds")
	ErrDeviceExportBusy     = errors.New("device exports are busy")
	deviceExports           = make(chan struct{}, 2)
)

// ExportDevices prepares one filtered snapshot before committing its read audit.
// The fixed projection excludes credentials and full reports. CSV marks cells
// that spreadsheets could interpret as formulas; JSON preserves their values.
func ExportDevices(ctx context.Context, db *sql.DB, permissions *access.Store, actor string, scope access.Scope, sources DeviceSources, filter DeviceFilter, format string) ([]byte, error) {
	if filter.After != "" || format != "csv" && format != "json" {
		return nil, ErrReportFilter
	}
	select {
	case deviceExports <- struct{}{}:
		defer func() { <-deviceExports }()
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, ErrDeviceExportBusy
	}
	var data []byte
	_, err := readDevices(ctx, db, permissions, actor, scope, sources, filter, 5000, "inventory.devices.export_"+format, func(exportCtx context.Context, page *DevicePage) error {
		var err error
		data, err = encodeDeviceExport(exportCtx, page.Entries, format)
		return err
	})
	if err != nil {
		return nil, err
	}
	return data, nil
}

type exportedDevice struct {
	Source           string     `json:"management_source"`
	ID               string     `json:"device_id"`
	TenantID         int        `json:"organization_id"`
	SiteID           int        `json:"site_id"`
	Name             string     `json:"name"`
	Platform         string     `json:"platform"`
	OSVersion        string     `json:"os_version"`
	Serial           string     `json:"serial_number"`
	Model            string     `json:"model"`
	ManagementStatus string     `json:"management_status"`
	AgentStatus      string     `json:"agent_status"`
	LastContact      *time.Time `json:"last_contact"`
}

func encodeDeviceExport(ctx context.Context, entries []DeviceEntry, format string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if format == "csv" {
		if err := writer.Write([]string{"Management source", "Device ID", "Organization ID", "Site ID", "Name", "Platform", "OS version", "Serial number", "Model", "Management status", "Agent status", "Last contact (UTC)"}); err != nil {
			return nil, err
		}
	} else {
		buffer.WriteByte('[')
	}
	for i, d := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var seen *time.Time
		if d.LastSeen != nil {
			utc := d.LastSeen.UTC()
			seen = &utc
		}
		if format == "csv" {
			stamp := ""
			if seen != nil {
				stamp = seen.Format(time.RFC3339Nano)
			}
			row := []string{d.Kind, d.ID, strconv.Itoa(d.TenantID), strconv.Itoa(d.SiteID), d.Name, d.Platform, d.OSVersion, d.Serial, d.Model, d.Status, d.AgentStatus, stamp}
			for i := range row {
				row[i] = exporttext.SpreadsheetCell(row[i])
			}
			if err := writer.Write(row); err != nil {
				return nil, err
			}
			writer.Flush()
			if err := writer.Error(); err != nil {
				return nil, err
			}
		} else {
			encoded, err := json.Marshal(exportedDevice{Source: d.Kind, ID: d.ID, TenantID: d.TenantID, SiteID: d.SiteID, Name: d.Name, Platform: d.Platform, OSVersion: d.OSVersion, Serial: d.Serial, Model: d.Model, ManagementStatus: d.Status, AgentStatus: d.AgentStatus, LastContact: seen})
			if err != nil {
				return nil, err
			}
			if i != 0 {
				buffer.WriteByte(',')
			}
			buffer.Write(encoded)
		}
		if buffer.Len() > 16<<20 {
			return nil, ErrDeviceExportTooLarge
		}
	}
	if format == "csv" {
		writer.Flush()
		if err := writer.Error(); err != nil {
			return nil, err
		}
	} else {
		buffer.WriteByte(']')
	}
	if buffer.Len() > 16<<20 {
		return nil, ErrDeviceExportTooLarge
	}
	return buffer.Bytes(), nil
}

// Bound individual metadata before pgx receives it, as well as total encoded
// output. Oversized values cause an error; exports never silently truncate them.
const boundedExportDeviceColumns = `kind,
 CASE WHEN octet_length(id)<=255 THEN id ELSE '' END,tenant_id,site_id,
 CASE WHEN octet_length(name)<=4096 THEN name ELSE '' END,platform,
 CASE WHEN octet_length(os_version)<=4096 THEN os_version ELSE '' END,
 CASE WHEN octet_length(serial)<=4096 THEN serial ELSE '' END,
 CASE WHEN octet_length(model)<=4096 THEN model ELSE '' END,
 status,agent_status,last_seen,valid,
 CASE WHEN octet_length(sort_name)<=4096 THEN sort_name ELSE '' END,
 (octet_length(id)<=255 AND octet_length(name)<=4096 AND octet_length(os_version)<=4096 AND octet_length(serial)<=4096 AND octet_length(model)<=4096 AND octet_length(sort_name)<=4096)`
