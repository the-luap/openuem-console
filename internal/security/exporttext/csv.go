// Package exporttext protects text cells in spreadsheet-readable exports.
package exporttext

import (
	"strings"
	"unicode"
)

// SpreadsheetCell adds a visible marker to formula-shaped or multiline text.
// Unlike an apostrophe escape, the marker survives a spreadsheet's CSV resave.
// JSON exports retain the original value.
func SpreadsheetCell(value string) string {
	trimmed := strings.TrimLeftFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) })
	for _, first := range trimmed {
		if strings.ContainsRune("=+-@＝＋－＠", first) {
			return "[text] " + value
		}
		break
	}
	if strings.ContainsAny(value, "\r\n\t") {
		return "[text] " + value
	}
	return value
}
