package handlers

import (
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

func windowsRingTestForm() url.Values {
	f := windowsPolicyTestForm()
	f.Del("mode")
	f.Del("hours")
	f.Set("ring_id", uuid.NewString())
	f.Set("expected_revision", "0")
	f.Set("enabled", "true")
	f.Set("name", "Synthetic update ring")
	return f
}

func TestWindowsRingEditorPreservesTypedRevision(t *testing.T) {
	f := windowsRingTestForm()
	r, err := parseWindowsUpdateRing(f)
	if err != nil || r.Revision != 1 || !r.Enabled {
		t.Fatal("new ring intent rejected", err)
	}
	next := windows_views.UpdateRingFormValues(r, uuid.NewString())
	edit, err := parseWindowsUpdateRing(next)
	if err != nil || edit.Revision != 2 || edit.RingID != r.RingID || edit.Name != r.Name || !reflect.DeepEqual(edit.Policy, r.Policy) {
		t.Fatal("revision edit lost original settings", err)
	}
	next.Set("enabled", "false")
	next.Set("feature_deferral_days", "")
	edit, err = parseWindowsUpdateRing(next)
	if err != nil || edit.Enabled || edit.Policy.FeatureDeferralDays != nil || edit.Policy.QualityDeferralDays == nil || *edit.Policy.QualityDeferralDays != 0 || edit.Policy.ExcludeDrivers == nil || *edit.Policy.ExcludeDrivers {
		t.Fatal("disabled ring confused omitted, zero or false", err)
	}
	f.Set("expected_revision", "999999")
	if r, err := parseWindowsUpdateRing(f); err != nil || r.Revision != 1000000 {
		t.Fatal("last supported revision rejected", err)
	}
}

func TestWindowsRingEditorRejectsAmbiguousIntent(t *testing.T) {
	for name, change := range map[string]func(url.Values){
		"nil ring":          func(f url.Values) { f.Set("ring_id", uuid.Nil.String()) },
		"bad request":       func(f url.Values) { f.Set("request_key", "invalid") },
		"uppercase ring":    func(f url.Values) { f.Set("ring_id", "ABCDEF00-0000-4000-8000-000000000001") },
		"negative revision": func(f url.Values) { f.Set("expected_revision", "-1") },
		"revision limit":    func(f url.Values) { f.Set("expected_revision", "1000000") },
		"revision overflow": func(f url.Values) { f.Set("expected_revision", strings.Repeat("9", 100)) },
		"revision padding":  func(f url.Values) { f.Set("expected_revision", "01") },
		"revision absent":   func(f url.Values) { f.Del("expected_revision") },
		"name bytes":        func(f url.Values) { f.Set("name", strings.Repeat("é", 65)) },
		"name spaces":       func(f url.Values) { f.Set("name", " padded") },
		"name control":      func(f url.Values) { f.Set("name", "bad\nname") },
		"invalid UTF8":      func(f url.Values) { f.Set("name", string([]byte{255})) },
		"missing state":     func(f url.Values) { f.Del("enabled") },
		"ambiguous state":   func(f url.Values) { f.Set("enabled", "1") },
		"dependent policy":  func(f url.Values) { f.Set("quality_deadline_days", "") },
	} {
		t.Run(name, func(t *testing.T) {
			f := windowsRingTestForm()
			change(f)
			if _, err := parseWindowsUpdateRing(f); err == nil {
				t.Fatal("invalid ring admitted")
			}
		})
	}
}
