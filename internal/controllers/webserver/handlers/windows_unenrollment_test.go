package handlers

import (
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestWindowsUnenrollmentDraftLimitsAndExactFields(t *testing.T) {
	form := url.Values{"request_key": {uuid.NewString()}, "hours": {"24"}, "reason": {"Explicit retirement"}}
	if lifetime, err := parseWindowsUnenrollmentDraft(form); err != nil || lifetime != 24*time.Hour {
		t.Fatal("valid draft rejected", err)
	}
	for _, hours := range []string{"1", "168"} {
		form.Set("hours", hours)
		if _, err := parseWindowsUnenrollmentDraft(form); err != nil {
			t.Fatal("boundary lifetime rejected", err)
		}
	}
	for _, hours := range []string{"0", "169", "01", "+1", "1.5", " 1", "1e2"} {
		form.Set("hours", hours)
		if _, err := parseWindowsUnenrollmentDraft(form); err == nil {
			t.Fatal("ambiguous lifetime admitted", hours)
		}
	}
	form.Set("hours", "24")
	for _, reason := range []string{"", " leading", "trailing ", "two\nlines", "bad\x00text"} {
		form.Set("reason", reason)
		if _, err := parseWindowsUnenrollmentDraft(form); err == nil {
			t.Fatal("invalid reason admitted")
		}
	}
}
