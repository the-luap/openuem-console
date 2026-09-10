package handlers

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

func windowsPolicyTestForm() url.Values {
	return url.Values{
		"name": {"Synthetic full policy"}, "mode": {"apply"}, "hours": {"24"}, "request_key": {uuid.NewString()},
		"quality_deferral_days": {"0"}, "feature_deferral_days": {"365"}, "quality_deadline_days": {"0"}, "feature_deadline_days": {"30"},
		"quality_grace_days": {"0"}, "feature_grace_days": {"7"}, "quality_no_auto_reboot": {"false"}, "feature_no_auto_reboot": {"true"},
		"active_hours_start": {"20"}, "active_hours_end": {"6"}, "active_hours_maximum": {"12"}, "notification_level": {"0"}, "exclude_drivers": {"false"},
	}
}

func TestWindowsPolicyFormPreservesEveryTypedSettingAndEmptySelection(t *testing.T) {
	form := windowsPolicyTestForm()
	policy, lifetime, err := parseWindowsUpdatePolicy(form)
	if err != nil || lifetime != 24*time.Hour {
		t.Fatal("full policy form rejected", err)
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &values); err != nil || len(values) != 13 {
		t.Fatal("form dropped a typed policy field")
	}
	for _, field := range windows_views.UpdatePolicyFields() {
		if string(values[field.Name]) != form.Get(field.Name) {
			t.Fatal("typed policy value changed", field.Name)
		}
	}
	for _, field := range windows_views.UpdatePolicyFields() {
		if field.Name != "quality_deferral_days" && field.Name != "exclude_drivers" {
			form.Set(field.Name, "")
		}
	}
	policy, _, err = parseWindowsUpdatePolicy(form)
	if err != nil || policy.QualityDeferralDays == nil || *policy.QualityDeferralDays != 0 || policy.ExcludeDrivers == nil || *policy.ExcludeDrivers || policy.FeatureDeferralDays != nil || policy.QualityDeadlineDays != nil || policy.FeatureNoAutoReboot != nil {
		t.Fatal("explicit zero/false became unmanaged or omitted fields were defaulted", err)
	}
	form.Set("mode", "remove")
	if _, _, err := parseWindowsUpdatePolicy(form); err != nil {
		t.Fatal("source removal selection rejected", err)
	}
}

func TestWindowsPolicyFormRejectsAmbiguousAndDependentIntent(t *testing.T) {
	for name, change := range map[string]func(url.Values){
		"empty policy": func(f url.Values) {
			for _, field := range windows_views.UpdatePolicyFields() {
				f.Set(field.Name, "")
			}
		},
		"missing quality deadline": func(f url.Values) { f.Set("quality_deadline_days", "") },
		"missing feature deadline": func(f url.Values) { f.Set("feature_deadline_days", "") },
		"one active endpoint":      func(f url.Values) { f.Set("active_hours_start", "") },
		"zero active span":         func(f url.Values) { f.Set("active_hours_end", "20") },
		"oversized active span":    func(f url.Values) { f.Set("active_hours_end", "12") },
		"fraction":                 func(f url.Values) { f.Set("quality_deferral_days", "0.5") },
		"exponent":                 func(f url.Values) { f.Set("quality_deferral_days", "1e1") },
		"leading zero":             func(f url.Values) { f.Set("quality_deferral_days", "00") },
		"negative":                 func(f url.Values) { f.Set("quality_deferral_days", "-1") },
		"range":                    func(f url.Values) { f.Set("feature_deferral_days", "366") },
		"noncanonical bool":        func(f url.Values) { f.Set("exclude_drivers", "False") },
		"numeric bool":             func(f url.Values) { f.Set("exclude_drivers", "0") },
		"name control":             func(f url.Values) { f.Set("name", "policy\nname") },
		"name padding":             func(f url.Values) { f.Set("name", " policy") },
		"name bound":               func(f url.Values) { f.Set("name", strings.Repeat("x", 129)) },
		"invalid UTF8":             func(f url.Values) { f.Set("name", string([]byte{0xff})) },
		"mode":                     func(f url.Values) { f.Set("mode", "execute") },
		"lifetime":                 func(f url.Values) { f.Set("hours", "169") },
		"noncanonical lifetime":    func(f url.Values) { f.Set("hours", "024") },
		"request nil":              func(f url.Values) { f.Set("request_key", uuid.Nil.String()) },
		"request uppercase":        func(f url.Values) { f.Set("request_key", strings.ToUpper("1abcdef0-abcd-4000-8000-000000000001")) },
	} {
		t.Run(name, func(t *testing.T) {
			form := windowsPolicyTestForm()
			change(form)
			if _, _, err := parseWindowsUpdatePolicy(form); err == nil {
				t.Fatal("invalid policy intent admitted")
			}
		})
	}
}
