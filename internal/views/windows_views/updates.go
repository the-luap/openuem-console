package windows_views

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/open-uem/openuem-console/internal/mdm/windows"
)

func updateState(state string) string {
	labels := map[string]string{
		"preflight_pending": "Waiting for platform evidence", "configuration_pending": "Waiting for configuration", "verification_pending": "Waiting for policy read-back",
		"preflight_failed": "Platform check failed", "configuration_failed": "Configuration failed", "unsupported": "Platform or setting not supported",
		"verified": "Policy values verified", "removed": "This source's configuration removed", "drifted": "Policy values differ", "verification_incomplete": "Policy evidence incomplete", "verification_failed": "Policy read-back failed", "verification_stale": "Evidence collection exceeded its time window",
		"queued": "Queued", "blocked": "Waiting for an earlier step", "sent": "Sent; awaiting evidence", "acknowledged": "Acknowledged by device", "failed": "Failed", "unknown": "Device outcome uncertain", "abandoned": "Uncertainty explicitly resolved", "canceled": "Undelivered steps canceled", "expired": "Expired",
		"configured_value_mismatch": "Configured value differs", "effective_value_mismatch": "Effective value differs", "value_absent": "Value absent", "still_configured": "Source configuration still present", "unreadable": "No readable value",
	}
	if label, ok := labels[state]; ok {
		return label
	}
	if state == "" {
		return "Not available"
	}
	return strings.ReplaceAll(state, "_", " ")
}

func updateMode(mode string) string {
	if mode == "remove" {
		return "Remove this source's settings"
	}
	return "Apply settings"
}

func platformEvidenceLabel(value string) string {
	if value == "" || value == "unknown" {
		return "Not established"
	}
	return strings.ReplaceAll(value, "_", " ")
}

func updateStep(index int) string {
	if index == 0 {
		return "Platform check"
	}
	if index == 1 {
		return "Configuration"
	}
	return fmt.Sprintf("Policy read-back · batch %d", index-1)
}

func observedInteger(n *int) string {
	if n == nil {
		return "No readable value"
	}
	return strconv.Itoa(*n)
}

func canCancelUpdate(steps []windows.CSPCommand) bool {
	pending := false
	for _, step := range steps {
		if step.Phase == "sent" || step.Phase == "unknown" {
			return false
		}
		pending = pending || step.Phase == "queued" || step.Phase == "blocked"
	}
	return pending
}

func canConfigureUpdate(device windows.DeviceMetadata) bool {
	return device.RevokedAt == nil && device.CertificateRevokedAt == nil && device.CertificateExpiresAt.After(time.Now())
}

type policyDisplayRow struct{ Label, Value string }

// Explicit zero and false remain visible; an unset setting is unmanaged.
func updatePolicyRows(p windows.UpdatePolicy) []policyDisplayRow {
	rows := []policyDisplayRow{}
	integer := func(label string, value *int) {
		text := "Unmanaged"
		if value != nil {
			text = strconv.Itoa(*value)
		}
		rows = append(rows, policyDisplayRow{label, text})
	}
	boolean := func(label string, value *bool) {
		text := "Unmanaged"
		if value != nil {
			text = "No"
			if *value {
				text = "Yes"
			}
		}
		rows = append(rows, policyDisplayRow{label, text})
	}
	integer("Quality update deferral (days)", p.QualityDeferralDays)
	integer("Feature update deferral (days)", p.FeatureDeferralDays)
	integer("Quality update deadline (days)", p.QualityDeadlineDays)
	integer("Feature update deadline (days)", p.FeatureDeadlineDays)
	integer("Quality update grace period (days)", p.QualityGraceDays)
	integer("Feature update grace period (days)", p.FeatureGraceDays)
	boolean("Wait for quality deadline and grace period before automatic reboot", p.QualityNoAutoReboot)
	boolean("Wait for feature deadline and grace period before automatic reboot", p.FeatureNoAutoReboot)
	integer("Active hours start (device-local hour)", p.ActiveHoursStart)
	integer("Active hours end (device-local hour)", p.ActiveHoursEnd)
	integer("Maximum active-hours range (hours)", p.ActiveHoursMaximum)
	integer("Notification level (0: default; 1: restart warnings only; 2: none)", p.NotificationLevel)
	boolean("Exclude drivers from quality updates", p.ExcludeDrivers)
	return rows
}
