package apple

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var ErrUpdatePromotionNotReady = errors.New("Apple update pilot or destination is not ready for promotion")
var ErrUpdatePromotionIntegrity = errors.New("Apple update promotion evidence is unavailable")

type UpdatePilotDeviceEvidence struct {
	DeviceID          string        `json:"-" xml:"-" yaml:"-"`
	Observation       OSObservation `json:"-" xml:"-" yaml:"-"`
	IdentityExpiresAt time.Time     `json:"-" xml:"-" yaml:"-"`
	PolicyToken       string        `json:"-" xml:"-" yaml:"-"`
	ExceptionEndedAt  *time.Time    `json:"-" xml:"-" yaml:"-"`
}

func (UpdatePilotDeviceEvidence) String() string {
	return "[protected Apple update pilot device evidence]"
}
func (e UpdatePilotDeviceEvidence) GoString() string { return e.String() }

type UpdatePilotEvidence struct {
	AssessedAt time.Time                   `json:"-" xml:"-" yaml:"-"`
	Devices    []UpdatePilotDeviceEvidence `json:"-" xml:"-" yaml:"-"`
}

func (UpdatePilotEvidence) String() string     { return "[protected Apple update pilot evidence]" }
func (e UpdatePilotEvidence) GoString() string { return e.String() }

type updatePilotDeviceEvidenceWire struct {
	DeviceID, Version, Build, Source, PolicyToken string
	RecordedAt, IdentityExpiresAt                 time.Time
	ExceptionEndedAt                              *time.Time
}
type updatePilotEvidenceWire struct {
	AssessedAt time.Time
	Devices    []updatePilotDeviceEvidenceWire
}

func pilotEvidenceWire(e *UpdatePilotEvidence) *updatePilotEvidenceWire {
	if e == nil {
		return nil
	}
	w := &updatePilotEvidenceWire{AssessedAt: e.AssessedAt, Devices: make([]updatePilotDeviceEvidenceWire, 0, len(e.Devices))}
	for _, d := range e.Devices {
		w.Devices = append(w.Devices, updatePilotDeviceEvidenceWire{DeviceID: d.DeviceID, Version: d.Observation.Version, Build: d.Observation.Build, Source: d.Observation.Source, RecordedAt: d.Observation.RecordedAt, IdentityExpiresAt: d.IdentityExpiresAt, PolicyToken: d.PolicyToken, ExceptionEndedAt: d.ExceptionEndedAt})
	}
	return w
}
func decodePilotEvidence(w *updatePilotEvidenceWire) *UpdatePilotEvidence {
	if w == nil {
		return nil
	}
	e := &UpdatePilotEvidence{AssessedAt: w.AssessedAt, Devices: make([]UpdatePilotDeviceEvidence, 0, len(w.Devices))}
	for _, d := range w.Devices {
		e.Devices = append(e.Devices, UpdatePilotDeviceEvidence{DeviceID: d.DeviceID, Observation: OSObservation{Version: d.Version, Build: d.Build, Source: d.Source, RecordedAt: d.RecordedAt}, IdentityExpiresAt: d.IdentityExpiresAt, PolicyToken: d.PolicyToken, ExceptionEndedAt: d.ExceptionEndedAt})
	}
	return e
}

// At admission, at is read again after the final audit. Historical reads use the
// original receipt's recording time, never the current device or current clock.
func validateUpdatePilotEvidence(e *UpdatePilotEvidence, original *UpdatePlanGroupAssignment, at time.Time) error {
	if e == nil || original == nil || e.AssessedAt.IsZero() || e.AssessedAt.Before(original.CreatedAt) || e.AssessedAt.After(at) || len(e.Devices) < 1 || len(e.Devices) > 100 || len(e.Devices) != len(original.Commands) {
		return ErrUpdatePromotionIntegrity
	}
	policy := original.Plan.Definition.Policy()
	for i, d := range e.Devices {
		if d.DeviceID != original.Commands[i].Selection.DeviceID || !profileRevisionUUID(d.DeviceID) || (i > 0 && d.DeviceID <= e.Devices[i-1].DeviceID) || d.PolicyToken != updatePolicyGroupToken(original.Scope, d.DeviceID, &policy) || !d.IdentityExpiresAt.After(at) || d.Observation.RecordedAt.After(e.AssessedAt) || len(d.Observation.Version) > 32 || len(d.Observation.Build) > 32 || (d.Observation.Source != "device_information" && d.Observation.Source != "declarative_status") {
			return ErrUpdatePromotionIntegrity
		}
		if result, _ := assessUpdateOS("available", &d.Observation, policy.TargetVersion, policy.TargetBuild, original.CreatedAt, at); result != "target_reported" {
			return ErrUpdatePromotionIntegrity
		}
		if d.ExceptionEndedAt != nil && (d.ExceptionEndedAt.IsZero() || d.ExceptionEndedAt.After(e.AssessedAt) || d.Observation.RecordedAt.Before(*d.ExceptionEndedAt)) {
			return ErrUpdatePromotionIntegrity
		}
	}
	return nil
}

// The caller retains the original pilot's device and policy locks, together
// with current read/update authority. No destination policy has been changed.
func (s *Store) captureUpdatePilotEvidence(ctx context.Context, tx *sql.Tx, p *UpdatePilotReadiness) (*UpdatePilotEvidence, error) {
	if p == nil || !p.AllReady {
		return nil, ErrUpdatePromotionNotReady
	}
	e := &UpdatePilotEvidence{AssessedAt: p.Progress.AssessedAt, Devices: make([]UpdatePilotDeviceEvidence, 0, len(p.Progress.Devices))}
	for _, device := range p.Progress.Devices {
		if !assessUpdatePilotDevice(device).Ready || device.CurrentPolicy == nil || device.RecordedAt == nil {
			return nil, ErrUpdatePromotionNotReady
		}
		d := UpdatePilotDeviceEvidence{DeviceID: device.DeviceID, Observation: OSObservation{Version: device.ReportedVersion, Build: device.ReportedBuild, Source: device.ReportSource, RecordedAt: *device.RecordedAt}, PolicyToken: updatePolicyGroupToken(p.Progress.Assignment.Scope, device.DeviceID, device.CurrentPolicy)}
		var enrolled bool
		if err := tx.QueryRowContext(ctx, `SELECT status='enrolled',certificate_expires_at FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND site_id=$3`, device.DeviceID, p.Progress.Assignment.Scope.TenantID, p.Progress.Assignment.Scope.SiteID).Scan(&enrolled, &d.IdentityExpiresAt); err != nil {
			return nil, notFound(err)
		}
		if !enrolled {
			return nil, ErrUpdatePromotionNotReady
		}
		if ended := updatePilotExceptionEnd(device.Exception); !ended.IsZero() {
			d.ExceptionEndedAt = &ended
		}
		e.Devices = append(e.Devices, d)
	}
	if err := validateUpdatePilotEvidence(e, &p.Progress.Assignment, e.AssessedAt); err != nil {
		return nil, err
	}
	return e, nil
}
