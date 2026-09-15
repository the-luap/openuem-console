package handlers

import (
	"strings"
	"testing"
)

func TestWindowsCSPResolutionAndRevisionBoundaries(t *testing.T) {
	for _, note := range []string{"Reviewed the device; accepted unresolved effects", "Reviewed <script>literal note</script>", strings.Repeat("ä", 160)} {
		if !validWindowsCSPResolution(note) {
			t.Fatal("valid resolution rejected")
		}
	}
	for _, note := range []string{"", " leading", "trailing ", "new\nline", "tab\there", "\u0085", "\xff", strings.Repeat("ä", 161)} {
		if validWindowsCSPResolution(note) {
			t.Fatal("invalid resolution admitted")
		}
	}
	for _, value := range []string{"1", "9223372036854775807"} {
		if _, err := parseWindowsCSPRevision(value); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"", "0", "-1", "01", "+1", "1.0", "9223372036854775808"} {
		if _, err := parseWindowsCSPRevision(value); err == nil {
			t.Fatal("ambiguous state revision admitted")
		}
	}
}
