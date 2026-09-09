package windows

import (
	"encoding/base64"
	"errors"
	"mime"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxCSPCommands       = 32
	MaxCSPDepth          = 4
	MaxCSPRequestBytes   = 128 << 10
	MaxCSPResultBytes    = 256 << 10
	maxCSPProtectedBytes = 2 << 20
)

var (
	ErrCSPCommand     = errors.New("invalid or unsupported native Windows CSP command")
	ErrCSPConflict    = errors.New("native Windows CSP command conflicts with its recorded request or revision")
	ErrCSPAlreadySent = errors.New("native Windows CSP command may already have executed")
	ErrCSPQueueFull   = errors.New("native Windows CSP command queue is full")
	ErrCSPDeadline    = errors.New("native Windows CSP command delivery deadline has passed")
)

// CSPCommandSpec is an explicitly authorized request, not an arbitrary SyncML
// document. Each leaf has one target so every response has an unambiguous owner.
// Ordinary serialization and diagnostics deliberately omit protected payloads.
type CSPCommandSpec struct {
	Kind     string           `json:"-" xml:"-"`
	URI      string           `json:"-" xml:"-"`
	Format   string           `json:"-" xml:"-"`
	MIME     string           `json:"-" xml:"-"`
	Data     *SyncMLData      `json:"-" xml:"-"`
	Commands []CSPCommandSpec `json:"-" xml:"-"`
}

func (CSPCommandSpec) String() string     { return "[protected Windows CSP command]" }
func (v CSPCommandSpec) GoString() string { return v.String() }

func cspUnreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", rune(c))
}

// Use one canonical URI spelling and no external URL, property query, wildcard,
// path traversal or alternate encoding of a protected enrollment-account root.
func validateCSPURI(uri, kind string) (bool, error) {
	if len(uri) == 0 || len(uri) > 1024 || !strings.HasPrefix(uri, "./") {
		return false, ErrCSPCommand
	}
	parts := strings.Split(uri[2:], "/")
	for _, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err != nil || decoded == "" || decoded == "." || decoded == ".." || !utf8.ValidString(decoded) || strings.IndexFunc(decoded, unicode.IsControl) >= 0 || strings.ContainsAny(decoded, "/\\%?#:*") {
			return false, ErrCSPCommand
		}
		var canonical strings.Builder
		const hex = "0123456789ABCDEF"
		for _, b := range []byte(decoded) {
			if cspUnreserved(b) {
				canonical.WriteByte(b)
			} else {
				canonical.WriteByte('%')
				canonical.WriteByte(hex[b>>4])
				canonical.WriteByte(hex[b&15])
			}
		}
		if canonical.String() != part {
			return false, ErrCSPCommand
		}
	}
	if parts[0] == "DevInfo" || parts[0] == "DevDetail" {
		if kind != "Get" {
			return false, ErrCSPCommand
		}
		return false, nil
	}
	if len(parts) < 4 || (parts[0] != "Device" && parts[0] != "User") || parts[1] != "Vendor" || parts[2] != "MSFT" {
		return false, ErrCSPCommand
	}
	// Enrollment accounts and transport configuration have their own lifecycle;
	// custom commands cannot overwrite or remove the current management channel.
	for _, protected := range []string{"DMClient", "DMAcc", "Enrollment", "Provisioning"} {
		if strings.EqualFold(parts[3], protected) {
			return false, ErrCSPCommand
		}
	}
	return parts[0] == "User", nil
}

func cspValueValid(kind, format, mimeType string, data *SyncMLData) bool {
	if kind == "Get" || kind == "Delete" {
		return format == "" && mimeType == "" && data == nil
	}
	if kind == "Exec" && data == nil {
		return format == "" && mimeType == ""
	}
	if format == "node" {
		return kind == "Add" && data == nil && mimeType == ""
	}
	if data == nil || data.OriginalError != "" || len(data.Text)+len(data.XML) > MaxCSPRequestBytes {
		return false
	}
	if mimeType != "" {
		media, parameters, err := mime.ParseMediaType(mimeType)
		if err != nil || len(parameters) != 0 || media != mimeType || len(media) > 128 {
			return false
		}
	}
	if data.XML != "" {
		return format == "xml" && data.Text == ""
	}
	switch format {
	case "chr":
		return validSyncMLXMLText(data.Text)
	case "xml":
		return false // XML values use the self-contained XML field.
	case "bool":
		return data.Text == "true" || data.Text == "false"
	case "int":
		number, err := strconv.ParseInt(data.Text, 10, 32)
		return err == nil && strconv.FormatInt(number, 10) == data.Text
	case "b64":
		decoded, err := base64.StdEncoding.Strict().DecodeString(data.Text)
		defer clear(decoded)
		return err == nil && base64.StdEncoding.EncodeToString(decoded) == data.Text
	case "null":
		return data.Text == ""
	default:
		return false
	}
}

type cspCompiler struct {
	count int
	user  bool
}

func (c *cspCompiler) command(spec CSPCommandSpec, depth int, inAtomic bool, added map[string]bool) (SyncMLCommand, error) {
	c.count++
	if c.count > MaxCSPCommands || depth > MaxCSPDepth {
		return SyncMLCommand{}, ErrCSPCommand
	}
	command := SyncMLCommand{Kind: spec.Kind, ID: strconv.Itoa(c.count)}
	switch spec.Kind {
	case "Atomic", "Sequence":
		if spec.URI != "" || spec.Format != "" || spec.MIME != "" || spec.Data != nil || len(spec.Commands) == 0 || spec.Kind == "Atomic" && inAtomic {
			return SyncMLCommand{}, ErrCSPCommand
		}
		if spec.Kind == "Atomic" {
			inAtomic = true
			added = map[string]bool{}
		}
		for _, child := range spec.Commands {
			if spec.Kind == "Sequence" && child.Kind == "Sequence" {
				return SyncMLCommand{}, ErrCSPCommand
			}
			parsed, err := c.command(child, depth+1, inAtomic, added)
			if err != nil {
				return SyncMLCommand{}, err
			}
			command.Commands = append(command.Commands, parsed)
		}
	case "Get", "Add", "Replace", "Delete", "Exec":
		if len(spec.Commands) != 0 || spec.Kind == "Get" && inAtomic || !cspValueValid(spec.Kind, spec.Format, spec.MIME, spec.Data) {
			return SyncMLCommand{}, ErrCSPCommand
		}
		user, err := validateCSPURI(spec.URI, spec.Kind)
		if err != nil {
			return SyncMLCommand{}, err
		}
		c.user = c.user || user
		if inAtomic {
			decoded, _ := url.PathUnescape(spec.URI)
			key := strings.ToLower(decoded)
			if spec.Kind == "Replace" && added[key] {
				return SyncMLCommand{}, ErrCSPCommand
			}
			if spec.Kind == "Add" {
				added[key] = true
			}
		}
		item := SyncMLItem{Target: &SyncMLLocation{URI: spec.URI}, Data: spec.Data}
		if spec.Format != "" || spec.MIME != "" {
			item.Meta = &SyncMLMeta{Format: spec.Format, Type: spec.MIME}
		}
		command.Items = []SyncMLItem{item}
	default:
		return SyncMLCommand{}, ErrCSPCommand
	}
	return command, nil
}

// The fixed envelope is only an encrypted storage representation. It must never
// be sent to a device; delivery replaces IDs and uses the authenticated session.
func encodeCSPRequest(spec CSPCommandSpec) ([]byte, bool, error) {
	compiler := cspCompiler{}
	command, err := compiler.command(spec, 0, false, nil)
	if err != nil {
		return nil, false, err
	}
	message := &SyncMLMessage{Header: SyncMLHeader{SessionID: "openuem-csp-v1", MessageID: "1", Target: SyncMLLocation{URI: "urn:openuem:windows:csp"}, Source: SyncMLLocation{URI: "urn:openuem:console"}}, Commands: []SyncMLCommand{command}, Final: true}
	encoded, err := EncodeSyncML(message)
	if err != nil || len(encoded) > MaxCSPRequestBytes {
		return nil, false, ErrCSPCommand
	}
	return encoded, compiler.user, nil
}

func decodeCSPRequest(data []byte) (SyncMLCommand, bool, error) {
	message, err := ParseSyncML(data)
	if err != nil || len(data) > MaxCSPRequestBytes || message.Header.SessionID != "openuem-csp-v1" || message.Header.MessageID != "1" || message.Header.Target.URI != "urn:openuem:windows:csp" || message.Header.Source.URI != "urn:openuem:console" || message.Header.Credential != nil || len(message.Commands) != 1 || !message.Final {
		return SyncMLCommand{}, false, ErrAuthoritySecret
	}
	var spec func(SyncMLCommand) CSPCommandSpec
	spec = func(command SyncMLCommand) CSPCommandSpec {
		result := CSPCommandSpec{Kind: command.Kind}
		if len(command.Items) == 1 && command.Items[0].Target != nil {
			item := command.Items[0]
			result.URI = item.Target.URI
			result.Data = item.Data
			if item.Meta != nil {
				result.Format = item.Meta.Format
				result.MIME = item.Meta.Type
			}
		}
		for _, child := range command.Commands {
			result.Commands = append(result.Commands, spec(child))
		}
		return result
	}
	canonical, user, err := encodeCSPRequest(spec(message.Commands[0]))
	if err != nil || string(canonical) != string(data) {
		return SyncMLCommand{}, false, ErrAuthoritySecret
	}
	return message.Commands[0], user, nil
}
