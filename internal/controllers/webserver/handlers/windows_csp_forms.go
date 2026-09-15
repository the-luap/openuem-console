package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/views/windows_views"
)

const maxWindowsCSPJSONBytes = 256 << 10
const maxWindowsCSPFormBytes = 3*maxWindowsCSPJSONBytes + 8192

func windowsFormByteLimit(path string) int64 {
	switch appleRoute(path) {
	case "/windows/:id/commands/preview", "/windows/:id/commands/create":
		return maxWindowsCSPFormBytes
	default:
		return 8192
	}
}

func windowsCSPFormNames() []string {
	return []string{"request_key", "seconds", "command", "confirm_command"}
}

// encoding/json replaces unpaired UTF-16 escapes with U+FFFD. Reject those
// inputs instead of silently changing requested text before compilation.
func validWindowsCSPJSONUnicode(data []byte) bool {
	if !utf8.Valid(data) || !json.Valid(data) {
		return false
	}
	quoted := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || data[i] != '\\' {
			continue
		}
		i++
		if data[i] != 'u' {
			continue
		}
		value, _ := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value >= 0xd800 && value <= 0xdbff {
			if len(data) < i+7 || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

// Each object is decoded explicitly: field names are exact, duplicate keys
// (including escaped aliases), JSON nulls and unrelated protocol fields fail.
func parseWindowsCSPJSON(raw string) (windows.CSPCommandSpec, error) {
	bad := fmt.Errorf("Use one command object with unique lowercase fields: kind, uri, format, mime, text, xml and commands. Values must be strings; commands must be an array of command objects.")
	if len(raw) == 0 || len(raw) > maxWindowsCSPJSONBytes || !validWindowsCSPJSONUnicode([]byte(raw)) {
		return windows.CSPCommandSpec{}, bad
	}
	d := json.NewDecoder(bytes.NewBufferString(raw))
	count := 0
	var command func(int) (windows.CSPCommandSpec, error)
	command = func(depth int) (windows.CSPCommandSpec, error) {
		var spec windows.CSPCommandSpec
		count++
		if count > windows.MaxCSPCommands || depth > windows.MaxCSPDepth {
			return spec, bad
		}
		start, err := d.Token()
		if err != nil || start != json.Delim('{') {
			return spec, bad
		}
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return spec, bad
			}
			seen[name] = true
			if name == "commands" {
				start, err := d.Token()
				if err != nil || start != json.Delim('[') {
					return spec, bad
				}
				for d.More() {
					child, err := command(depth + 1)
					if err != nil {
						return spec, err
					}
					spec.Commands = append(spec.Commands, child)
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return spec, bad
				}
				continue
			}
			switch name {
			case "kind", "uri", "format", "mime", "text", "xml":
			default:
				return spec, bad
			}
			value, err := d.Token()
			text, ok := value.(string)
			if err != nil || !ok {
				return spec, bad
			}
			switch name {
			case "kind":
				spec.Kind = text
			case "uri":
				spec.URI = text
			case "format":
				spec.Format = text
			case "mime":
				spec.MIME = text
			case "text":
				if seen["xml"] {
					return spec, bad
				}
				spec.Data = &windows.SyncMLData{Text: text}
			case "xml":
				if seen["text"] {
					return spec, bad
				}
				spec.Data = &windows.SyncMLData{XML: text}
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') || !seen["kind"] {
			return spec, bad
		}
		if seen["xml"] && (spec.Format != "xml" || spec.Data.XML == "") {
			return spec, bad
		}
		if spec.Kind == "Atomic" || spec.Kind == "Sequence" {
			for _, name := range []string{"uri", "format", "mime", "text", "xml"} {
				if seen[name] {
					return spec, bad
				}
			}
		}
		// An explicit empty children array on a leaf is misleading intent, even
		// though the underlying Go slice alone cannot distinguish it from absence.
		if seen["commands"] && (len(spec.Commands) == 0 || (spec.Kind != "Atomic" && spec.Kind != "Sequence")) {
			return spec, bad
		}
		return spec, nil
	}
	spec, err := command(0)
	if err != nil {
		return windows.CSPCommandSpec{}, err
	}
	if _, err := d.Token(); err != io.EOF {
		return windows.CSPCommandSpec{}, bad
	}
	return spec, nil
}

func parseWindowsCSPDraft(form url.Values) (windows.CSPCommandSpec, time.Duration, error) {
	key, err := uuid.Parse(form.Get("request_key"))
	if err != nil || key == uuid.Nil || key.String() != form.Get("request_key") {
		return windows.CSPCommandSpec{}, 0, fmt.Errorf("The request identifier is invalid. Start a new command.")
	}
	seconds, err := strconv.Atoi(form.Get("seconds"))
	if err != nil || seconds < 60 || seconds > 604800 || strconv.Itoa(seconds) != form.Get("seconds") {
		return windows.CSPCommandSpec{}, 0, fmt.Errorf("Choose an admission lifetime from 60 to 604800 whole seconds")
	}
	spec, err := parseWindowsCSPJSON(form.Get("command"))
	return spec, time.Duration(seconds) * time.Second, err
}

func (h *Handler) WindowsNewCSPCommand(c echo.Context) error {
	info, _, device, err := h.windowsUpdateFormContext(c)
	if err != nil {
		return err
	}
	form := url.Values{"request_key": {uuid.NewString()}, "seconds": {"86400"}, "command": {"{\n  \"kind\": \"Get\",\n  \"uri\": \"./DevInfo/DevId\"\n}"}}
	return renderApple(c, windows_views.CSPCommandForm(c, info, *device, windows_views.CSPCommandDraft{Form: form}))
}

func (h *Handler) WindowsPreviewCSPCommand(c echo.Context) error {
	info, _, device, err := h.windowsUpdateFormContext(c)
	if err != nil {
		return err
	}
	form, err := windowsForm(c, append(windowsCSPFormNames(), "edit_command")...)
	if err != nil {
		return err
	}
	draft := windows_views.CSPCommandDraft{Form: form}
	spec, _, parseErr := parseWindowsCSPDraft(form)
	if parseErr == nil {
		draft.Preview, err = windows.PreviewCSPCommand(spec)
		if err != nil {
			parseErr = fmt.Errorf("The command tree is not supported. Check target paths, operation/value rules, group nesting and the 128 KiB compiled request limit.")
		}
	}
	if parseErr != nil {
		c.Response().Status = 400
		draft.Error = parseErr.Error()
		return renderApple(c, windows_views.CSPCommandForm(c, info, *device, draft))
	}
	if form.Get("edit_command") == "yes" {
		return renderApple(c, windows_views.CSPCommandForm(c, info, *device, draft))
	}
	if form.Get("edit_command") != "" {
		return echo.NewHTTPError(400, "Invalid command review action")
	}
	if draft.Preview.UserTarget && device.EnrollmentType != "Full" {
		c.Response().Status = 400
		draft.Error = "User-targeted commands require Full enrollment. Review this device's identity or choose device targets."
		return renderApple(c, windows_views.CSPCommandForm(c, info, *device, draft))
	}
	return renderApple(c, windows_views.CSPCommandPreview(c, info, *device, draft))
}

func (h *Handler) WindowsCreateCSPCommand(c echo.Context) error {
	info, scope, err := h.windowsInfo(c)
	if err != nil {
		return err
	}
	if err := h.windowsReady(); err != nil {
		return err
	}
	form, err := windowsForm(c, windowsCSPFormNames()...)
	if err != nil {
		return err
	}
	spec, lifetime, err := parseWindowsCSPDraft(form)
	if err != nil {
		return echo.NewHTTPError(400, err.Error())
	}
	if form.Get("confirm_command") != "yes" {
		return echo.NewHTTPError(400, "Review and confirm every operation and the selected device")
	}
	// The store checks new-work identity after exact replay. Do not add an
	// eligibility read here that would turn an old request into a failed retry.
	command, err := h.Windows.EnqueueCSPCommand(c.Request().Context(), h.appleActor(c), scope, c.Param("id"), form.Get("request_key"), spec, lifetime)
	if err != nil {
		return windowsCSPFailure(err)
	}
	return appleRedirect(c, info, "/windows/"+command.DeviceID+"/commands/"+command.ID)
}
