package inventory

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrReportFilter = errors.New("invalid inventory report filter")

type ReportFilter struct {
	Search string
	After  int64
}

func (f ReportFilter) Valid() bool {
	return f.After >= 0 && len(f.Search) <= 256 && utf8.ValidString(f.Search) && strings.IndexFunc(f.Search, unicode.IsControl) < 0
}
