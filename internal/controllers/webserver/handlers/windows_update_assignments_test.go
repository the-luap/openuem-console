package handlers

import (
	"github.com/google/uuid"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func windowsAssignmentTestForm(devices ...string) url.Values {
	return url.Values{"ring_revision": {"1"}, "request_key": {uuid.NewString()}, "mode": {"apply"}, "hours": {"24"}, "devices": {strings.Join(devices, "\n")}}
}

func TestWindowsAssignmentParserPreservesExplicitSet(t *testing.T) {
	first, second := "10000000-0000-4000-8000-000000000001", "20000000-0000-4000-8000-000000000002"
	form := windowsAssignmentTestForm(first, second)
	form.Set("devices", " \t"+second+"\r\n"+first+"\r\n")
	revision, devices, lifetime, err := parseWindowsAssignment(form)
	if err != nil || revision != 1 || lifetime != 24*time.Hour || !reflect.DeepEqual(devices, []string{first, second}) {
		t.Fatal("explicit target set changed", err)
	}
	targets := make([]string, 100)
	for i := range targets {
		targets[i] = uuid.NewString()
	}
	form.Set("devices", strings.Join(targets, "\n"))
	form.Set("mode", "remove")
	form.Set("ring_revision", "1000000")
	if revision, targets, _, err := parseWindowsAssignment(form); err != nil || revision != 1000000 || len(targets) != 100 {
		t.Fatal("bounded historical removal rejected", err)
	}
}

func TestWindowsAssignmentParserRejectsAmbiguousSelection(t *testing.T) {
	for name, change := range map[string]func(url.Values){
		"empty":      func(f url.Values) { f.Set("devices", "") },
		"duplicates": func(f url.Values) { f.Set("devices", f.Get("devices")+"\n"+f.Get("devices")) },
		"blank line": func(f url.Values) { f.Set("devices", f.Get("devices")+"\n\n"+uuid.NewString()) },
		"comma list": func(f url.Values) { f.Set("devices", f.Get("devices")+","+uuid.NewString()) },
		"uppercase":  func(f url.Values) { f.Set("devices", "ABCDEF00-0000-4000-8000-000000000001") },
		"nil":        func(f url.Values) { f.Set("devices", uuid.Nil.String()) },
		"too many": func(f url.Values) {
			ids := make([]string, 101)
			for i := range ids {
				ids[i] = uuid.NewString()
			}
			f.Set("devices", strings.Join(ids, "\n"))
		},
		"too large":       func(f url.Values) { f.Set("devices", strings.Repeat("x", 4001)) },
		"bad revision":    func(f url.Values) { f.Set("ring_revision", "01") },
		"revision zero":   func(f url.Values) { f.Set("ring_revision", "0") },
		"revision large":  func(f url.Values) { f.Set("ring_revision", "1000001") },
		"mode":            func(f url.Values) { f.Set("mode", "execute") },
		"key":             func(f url.Values) { f.Set("request_key", uuid.Nil.String()) },
		"hours":           func(f url.Values) { f.Set("hours", "169") },
		"ambiguous hours": func(f url.Values) { f.Set("hours", "024") },
	} {
		t.Run(name, func(t *testing.T) {
			form := windowsAssignmentTestForm(uuid.NewString())
			change(form)
			if _, _, _, err := parseWindowsAssignment(form); err == nil {
				t.Fatal("ambiguous assignment admitted")
			}
		})
	}
}
