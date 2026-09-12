package windows

import (
	"encoding/base64"
	"strconv"
	"strings"
)

type cspOperationResult struct {
	WireID        string
	ParentID      string
	Kind          string
	URI           string
	Status        int
	OriginalError string
	HasResult     bool
	MoreData      bool
	ExpectedSize  *uint64
	Format        string
	MIME          string
	Text          string
	XML           string
}

type cspSessionCommand struct {
	UnenrollmentRequestID string `json:",omitempty"`
	Version               int
	CommandID             string
	MessageID             string
	ObservedMessageID     string
	StopReason            string
	Operations            []cspOperationResult
}

func (cspOperationResult) String() string     { return "[protected Windows CSP operation result]" }
func (v cspOperationResult) GoString() string { return v.String() }
func (cspSessionCommand) String() string      { return "[protected Windows CSP exchange]" }
func (v cspSessionCommand) GoString() string  { return v.String() }

func newCSPSessionCommand(id, messageID string, command SyncMLCommand) *cspSessionCommand {
	result := &cspSessionCommand{Version: 1, CommandID: id, MessageID: messageID}
	var appendCommand func(SyncMLCommand, string)
	appendCommand = func(command SyncMLCommand, parent string) {
		entry := cspOperationResult{WireID: command.ID, ParentID: parent, Kind: command.Kind}
		if len(command.Items) == 1 && command.Items[0].Target != nil {
			entry.URI = command.Items[0].Target.URI
		}
		result.Operations = append(result.Operations, entry)
		for _, child := range command.Commands {
			appendCommand(child, command.ID)
		}
	}
	appendCommand(command, "")
	return result
}

func sameCSPResultURI(got, want string) bool {
	if strings.HasPrefix(got, "./Vendor/MSFT/") {
		got = "./Device/" + strings.TrimPrefix(got, "./")
	}
	return got == want
}

func cspReferencesMatch(command SyncMLCommand, uri string) bool {
	for _, refs := range [][]string{command.SourceRefs, command.TargetRefs} {
		for _, ref := range refs {
			if uri == "" || !sameCSPResultURI(ref, uri) {
				return false
			}
		}
	}
	return true
}

// processCSPResponses consumes only references to the actual dispatched tree.
// Everything else still passes through the ordinary SyncML session validator.
func processCSPResponses(session *syncMLSession, request, response *SyncMLMessage) (*SyncMLMessage, error) {
	state := session.State.CSP
	if state == nil {
		return request, nil
	}
	remaining := *request
	remaining.Commands = nil
	seenStatus, seenResults := map[string]bool{}, map[string]bool{}
	initialPartial := ""
	for _, operation := range state.Operations {
		if operation.MoreData {
			initialPartial = operation.WireID
		}
	}
	continued := false
	for _, command := range request.Commands {
		var operation *cspOperationResult
		if command.Kind == "Status" || command.Kind == "Results" {
			for n := range state.Operations {
				if state.Operations[n].WireID == command.CommandRef {
					operation = &state.Operations[n]
					break
				}
			}
		}
		if operation == nil {
			if command.Kind != "Status" && command.Kind != "Alert" {
				for _, pending := range state.Operations {
					if pending.MoreData {
						state.StopReason = "incomplete_object"
					}
				}
			}
			remaining.Commands = append(remaining.Commands, command)
			continue
		}
		if command.MessageRef != state.MessageID || !cspReferencesMatch(command, operation.URI) {
			return nil, ErrSyncMLSession
		}
		state.ObservedMessageID = request.Header.MessageID
		switch command.Kind {
		case "Status":
			if seenStatus[operation.WireID] || command.CommandName != operation.Kind || command.Data == nil || command.Challenge != nil || len(command.Items) != 0 {
				return nil, ErrSyncMLSession
			}
			seenStatus[operation.WireID] = true
			code, err := strconv.Atoi(command.Data.Text)
			if err != nil {
				return nil, ErrSyncMLSession
			}
			// Asynchronous acceptance may advance to a final status. Once final,
			// a different status is conflicting evidence, not a replacement.
			if operation.Status != 0 && operation.Status != 202 && operation.Status != code {
				return nil, ErrSyncMLSession
			}
			if operation.Status != 202 && operation.OriginalError != "" && command.Data.OriginalError != "" && operation.OriginalError != command.Data.OriginalError {
				return nil, ErrSyncMLSession
			}
			operation.Status = code
			if command.Data.OriginalError != "" {
				operation.OriginalError = command.Data.OriginalError
			}
		case "Results":
			if seenResults[operation.WireID] || operation.Kind != "Get" || len(command.Items) != 1 || operation.HasResult && !operation.MoreData {
				return nil, ErrSyncMLSession
			}
			seenResults[operation.WireID] = true
			item := command.Items[0]
			if item.Source == nil || !sameCSPResultURI(item.Source.URI, operation.URI) || item.Target != nil || item.Data == nil || item.Data.OriginalError != "" {
				return nil, ErrSyncMLSession
			}
			for _, pending := range state.Operations {
				if pending.MoreData && pending.WireID != operation.WireID {
					state.StopReason = "incomplete_object"
					break
				}
			}
			if state.StopReason != "" {
				break
			}
			code, err := receiveCSPResult(operation, command.Meta, item)
			if err != nil {
				return nil, err
			}
			continued = continued || operation.WireID == initialPartial
			if code == "424" {
				state.StopReason = "size_mismatch"
				syncMLStatus(response, request.Header.MessageID, command.ID, command.Kind, code)
			}
			if code == "213" {
				syncMLStatus(response, request.Header.MessageID, command.ID, command.Kind, code)
			}
		}
	}
	if initialPartial != "" && !continued {
		state.StopReason = "incomplete_object"
	}
	if state.StopReason == "incomplete_object" {
		response.Commands = append(response.Commands, SyncMLCommand{Kind: "Alert", ID: strconv.Itoa(len(response.Commands) + 1), Data: &SyncMLData{Text: "1225"}})
	}
	if state.StopReason != "" {
		session.Phase = "failed"
	}
	total := 0
	for _, operation := range state.Operations {
		if operation.HasResult && operation.Status != 0 && operation.Status != 200 {
			return nil, ErrSyncMLSession
		}
		if request.Final && operation.MoreData && state.StopReason == "" {
			return nil, ErrSyncMLSession
		}
		total += cspResultLength(operation)
	}
	if total > MaxCSPResultBytes {
		return nil, ErrSyncMLSession
	}
	return &remaining, nil
}

func cspResultLength(operation cspOperationResult) int {
	if operation.Format == "b64" {
		if operation.MoreData {
			return len(operation.Text) * 3 / 4
		}
		length := base64.StdEncoding.DecodedLen(len(operation.Text))
		if strings.HasSuffix(operation.Text, "==") {
			length -= 2
		} else if strings.HasSuffix(operation.Text, "=") {
			length--
		}
		return length
	}
	return len(operation.Text) + len(operation.XML)
}

func receiveCSPResult(operation *cspOperationResult, commandMeta *SyncMLMeta, item SyncMLItem) (string, error) {
	format, mimeType := "", ""
	if commandMeta != nil {
		if commandMeta.Size != nil {
			return "", ErrSyncMLSession
		}
		format, mimeType = commandMeta.Format, commandMeta.Type
	}
	var size *uint64
	if item.Meta != nil {
		if item.Meta.Format != "" {
			format = item.Meta.Format
		}
		if item.Meta.Type != "" {
			mimeType = item.Meta.Type
		}
		size = item.Meta.Size
	}
	if operation.HasResult {
		if format != "" && format != operation.Format || mimeType != "" && mimeType != operation.MIME || size != nil {
			return "", ErrSyncMLSession
		}
		format, mimeType = operation.Format, operation.MIME
	}
	switch format {
	case "", "chr", "xml", "node", "int", "bool", "b64", "null":
	default:
		return "", ErrSyncMLSession
	}
	if size != nil && *size > MaxCSPResultBytes {
		return "", ErrSyncMLSession
	}
	if !operation.HasResult && item.MoreData && size == nil {
		return "", ErrSyncMLSession
	}
	if item.Data.XML != "" && (item.MoreData || operation.HasResult || format == "b64" || format == "int" || format == "bool" || format == "null") {
		return "", ErrSyncMLSession
	}
	textValue := operation.Text + item.Data.Text
	xmlValue := item.Data.XML
	length := len(textValue) + len(xmlValue)
	if format == "b64" {
		if len(textValue) > base64.StdEncoding.EncodedLen(MaxCSPResultBytes) {
			return "", ErrSyncMLSession
		}
		if item.MoreData {
			for _, c := range textValue {
				if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/') {
					return "", ErrSyncMLSession
				}
			}
			length = len(textValue) * 3 / 4
		} else {
			decoded, err := base64.StdEncoding.Strict().DecodeString(textValue)
			if err != nil || base64.StdEncoding.EncodeToString(decoded) != textValue {
				clear(decoded)
				return "", ErrSyncMLSession
			}
			length = len(decoded)
			clear(decoded)
		}
	}
	if length > MaxCSPResultBytes {
		return "", ErrSyncMLSession
	}
	expected := operation.ExpectedSize
	if !operation.HasResult {
		expected = size
	}
	if expected != nil && (uint64(length) > *expected || !item.MoreData && uint64(length) != *expected || item.MoreData && uint64(length) == *expected) {
		return "424", nil
	}
	if !item.MoreData {
		switch format {
		case "int":
			number, err := strconv.ParseInt(textValue, 10, 32)
			if err != nil || strconv.FormatInt(number, 10) != textValue {
				return "", ErrSyncMLSession
			}
		case "bool":
			if textValue != "true" && textValue != "false" {
				return "", ErrSyncMLSession
			}
		case "null":
			if textValue != "" {
				return "", ErrSyncMLSession
			}
		case "xml":
			if xmlValue == "" && !syncMLMarkupValid(textValue) {
				return "", ErrSyncMLSession
			}
		}
	}
	operation.Format, operation.MIME = format, mimeType
	operation.Text, operation.XML = textValue, xmlValue
	operation.HasResult, operation.MoreData = true, item.MoreData
	operation.ExpectedSize = expected
	if item.MoreData {
		return "213", nil
	}
	return "200", nil
}

// A positive transport status is distinct from asynchronous completion or a
// read-back verification. All group and leaf statuses must be accounted for.
func cspOutcome(state *cspSessionCommand) string {
	if state == nil {
		return ""
	}
	if state.StopReason != "" {
		return "unknown"
	}
	waiting, failed, asynchronous, rollbackFailed := false, false, false, false
	for _, operation := range state.Operations {
		switch operation.Status {
		case 0:
			waiting = true
		case 200:
			if operation.Kind == "Get" && (!operation.HasResult || operation.MoreData) {
				waiting = true
			}
		case 201:
			if operation.Kind != "Add" {
				failed = true
			}
		case 202:
			asynchronous = true
		case 516:
			rollbackFailed = true
		default:
			failed = true
		}
	}
	if waiting {
		return ""
	}
	if rollbackFailed {
		return "unknown"
	}
	if failed {
		return "failed"
	}
	if asynchronous {
		return "unknown"
	}
	return "acknowledged"
}

func (state *cspSessionCommand) validate() error {
	if state == nil {
		return nil
	}
	if state.Version != 1 || !canonicalInvitationID(state.CommandID) || len(state.Operations) == 0 || len(state.Operations) > MaxCSPCommands {
		return ErrAuthoritySecret
	}
	if state.UnenrollmentRequestID != "" && (state.UnenrollmentRequestID != state.CommandID || len(state.Operations) != 1 || state.Operations[0].Kind != "Exec" || state.Operations[0].URI != "./Device/Vendor/MSFT/DMClient/Unenroll" || state.Operations[0].ParentID != "") {
		return ErrAuthoritySecret
	}
	message, err := strconv.Atoi(state.MessageID)
	if err != nil || message < 1 || message > maxSyncMLSessionMessages || strconv.Itoa(message) != state.MessageID {
		return ErrAuthoritySecret
	}
	seen := map[string]bool{}
	partial, total := 0, 0
	for _, operation := range state.Operations {
		switch operation.Kind {
		case "Atomic", "Sequence", "Get", "Add", "Replace", "Delete", "Exec":
		default:
			return ErrAuthoritySecret
		}
		if !syncMLStoredIdentifier(operation.WireID, 64) || seen[operation.WireID] || operation.ParentID != "" && !seen[operation.ParentID] || operation.Status != 0 && (operation.Status < 100 || operation.Status > 999) {
			return ErrAuthoritySecret
		}
		seen[operation.WireID] = true
		if operation.Kind == "Atomic" || operation.Kind == "Sequence" {
			if operation.URI != "" || operation.HasResult {
				return ErrAuthoritySecret
			}
		} else if _, err := validateCSPURI(operation.URI, operation.Kind); err != nil && state.UnenrollmentRequestID == "" {
			return ErrAuthoritySecret
		}
		if operation.HasResult && operation.Kind != "Get" || operation.MoreData && !operation.HasResult {
			return ErrAuthoritySecret
		}
		if operation.MoreData {
			partial++
			if operation.ExpectedSize == nil {
				return ErrAuthoritySecret
			}
		}
		if operation.ExpectedSize != nil && *operation.ExpectedSize > MaxCSPResultBytes {
			return ErrAuthoritySecret
		}
		total += cspResultLength(operation)
	}
	if partial > 1 || total > MaxCSPResultBytes {
		return ErrAuthoritySecret
	}
	return nil
}
