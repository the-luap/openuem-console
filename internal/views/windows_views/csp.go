package windows_views

import (
	"fmt"

	"github.com/open-uem/openuem-console/internal/mdm/windows"
)

func cspState(state string) string {
	labels := map[string]string{
		"queued": "Queued; not sent", "blocked": "Blocked before delivery",
		"sent": "Sent; evidence pending", "acknowledged": "Command acknowledged",
		"failed": "Device reported failure", "unknown": "Effects uncertain",
		"abandoned": "Uncertain command released", "canceled": "Canceled before delivery",
		"expired": "Expired before delivery",
	}
	if label, ok := labels[state]; ok {
		return label
	}
	return "Status unavailable"
}

func cspStatus(status int) string {
	if status == 0 {
		return "No status received"
	}
	return fmt.Sprint(status)
}

func canCancelCSP(command windows.CSPCommand) bool {
	return command.UpdateRunID == "" && (command.Phase == "queued" || command.Phase == "blocked")
}

type cspRequestRow struct {
	Position string
	Command  windows.SyncMLCommand `json:"-" xml:"-" yaml:"-"`
}

func (cspRequestRow) String() string     { return "[protected Windows CSP request row]" }
func (v cspRequestRow) GoString() string { return v.String() }

func cspRequestRows(command windows.SyncMLCommand) []cspRequestRow {
	rows := []cspRequestRow{}
	var visit func(windows.SyncMLCommand, string)
	visit = func(command windows.SyncMLCommand, position string) {
		rows = append(rows, cspRequestRow{Position: position, Command: command})
		for i, child := range command.Commands {
			visit(child, fmt.Sprintf("%s.%d", position, i+1))
		}
	}
	visit(command, "1")
	return rows
}
