package exporttext

import "testing"

func TestSpreadsheetCellsKeepUntrustedValuesAsText(t *testing.T) {
	for _, value := range []string{"=1+1", "+1", "-1", "@SUM(A1)", "\u200b=1", "  ＝1", "\tname", "line\nbreak", "line\rbreak", "\u2060＠SUM(A1)"} {
		if got := SpreadsheetCell(value); got != "[text] "+value {
			t.Errorf("unsafe cell %q became %q", value, got)
		}
	}
	for _, value := range []string{"", "Ordinary device", "2026-09-12T12:00:00Z", "comma, and \"quotes\""} {
		if got := SpreadsheetCell(value); got != value {
			t.Errorf("ordinary text changed: %q", got)
		}
	}
}
