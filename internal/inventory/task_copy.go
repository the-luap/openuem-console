package inventory

import (
	"github.com/open-uem/ent/task"
	"strings"
)

// Only pinned schema column names enter this SQL fragment. Preserve nullable
// configuration directly; identity, execution time, version and order are fresh.
func legacyTaskCopyFields(rename bool) string {
	columns := make([]string, 0, len(task.Columns))
	for _, column := range task.Columns {
		switch column {
		case task.FieldID, task.FieldVersion, task.FieldWhen, task.FieldOrder:
			continue
		}
		if rename && column == task.FieldName {
			continue
		}
		columns = append(columns, `"`+column+`"`)
	}
	return strings.Join(columns, ",")
}
