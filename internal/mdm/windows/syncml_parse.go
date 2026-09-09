package windows

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ParseSyncML reads the Windows OMA DM 1.2 XML form. It performs no network I/O,
// credential verification, nonce transition, CSP mutation or status correlation.
// Authentication and command authorization must follow inside a transaction.
func ParseSyncML(data []byte) (*SyncMLMessage, error) {
	root, err := parseXML(data, MaxSyncMLBytes)
	if err != nil || !root.is(syncMLNS, "SyncML") || !syncMLFields(root, "SyncHdr", "SyncBody") || len(root.Children) != 2 || !root.Children[0].is(syncMLNS, "SyncHdr") || !root.Children[1].is(syncMLNS, "SyncBody") {
		return nil, ErrSyncML
	}
	m := &SyncMLMessage{}
	if err := parseSyncMLHeader(root.Children[0], &m.Header); err != nil {
		return nil, ErrSyncML
	}
	body := root.Children[1]
	if len(body.Attrs) != 0 || !body.container() || len(body.Children) == 0 {
		return nil, ErrSyncML
	}
	parser := syncMLParser{ids: map[string]bool{}}
	for n, child := range body.Children {
		if child.is(syncMLNS, "Final") {
			if n != len(body.Children)-1 || !syncMLEmpty(child) {
				return nil, ErrSyncML
			}
			m.Final = true
			continue
		}
		command, err := parser.command(child, 0)
		if err != nil {
			return nil, ErrSyncML
		}
		m.Commands = append(m.Commands, *command)
	}
	return m, nil
}

// Names ending in * may repeat. Field order is retained where meaningful
// (commands, items, references); singleton order accepts the variations in the
// Microsoft and OMA examples. Unknown and namespace-confusable fields fail.
func syncMLFields(e *xmlElement, names ...string) bool {
	if e == nil || len(e.Attrs) != 0 || !e.container() {
		return false
	}
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[strings.TrimSuffix(name, "*")] = strings.HasSuffix(name, "*")
	}
	seen := map[string]bool{}
	for _, child := range e.Children {
		repeated, ok := allowed[child.Name.Local]
		if !ok || child.Name.Space != syncMLNS || (seen[child.Name.Local] && !repeated) {
			return false
		}
		seen[child.Name.Local] = true
	}
	return true
}

func syncMLEmpty(e *xmlElement) bool {
	return len(e.Attrs) == 0 && len(e.Children) == 0 && e.Text == ""
}

func syncMLText(e *xmlElement, maximum int, allowEmpty bool) (string, error) {
	if e == nil || len(e.Attrs) != 0 || len(e.Children) != 0 || len(e.Text) > maximum || !utf8.ValidString(e.Text) || strings.TrimSpace(e.Text) != e.Text || strings.IndexFunc(e.Text, unicode.IsControl) >= 0 || (!allowEmpty && e.Text == "") {
		return "", ErrSyncML
	}
	return e.Text, nil
}

func syncMLField(e *xmlElement, name string, maximum int, required bool) (string, error) {
	node, err := e.optional(syncMLNS, name)
	if err != nil || (required && node == nil) {
		return "", ErrSyncML
	}
	if node == nil {
		return "", nil
	}
	return syncMLText(node, maximum, false)
}

func parseSyncMLLocation(e *xmlElement) (*SyncMLLocation, error) {
	if !syncMLFields(e, "LocURI", "LocName") {
		return nil, ErrSyncML
	}
	uri, err := syncMLField(e, "LocURI", 2048, true)
	if err != nil {
		return nil, err
	}
	name, err := syncMLField(e, "LocName", 320, false)
	if err != nil {
		return nil, err
	}
	return &SyncMLLocation{URI: uri, Name: name}, nil
}

func parseSyncMLHeader(e *xmlElement, h *SyncMLHeader) error {
	if !syncMLFields(e, "VerDTD", "VerProto", "SessionID", "MsgID", "Target", "Source", "RespURI", "Cred", "Meta") {
		return ErrSyncML
	}
	for name, expected := range map[string]string{"VerDTD": "1.2", "VerProto": "DM/1.2"} {
		value, err := syncMLField(e, name, 16, true)
		if err != nil || value != expected {
			return ErrSyncML
		}
	}
	for _, field := range []struct {
		name     string
		target   *string
		maximum  int
		required bool
	}{
		{"SessionID", &h.SessionID, 64, true}, {"MsgID", &h.MessageID, 64, true}, {"RespURI", &h.ResponseURI, 2048, false},
	} {
		value, err := syncMLField(e, field.name, field.maximum, field.required)
		if err != nil {
			return err
		}
		*field.target = value
	}
	number, err := strconv.ParseUint(h.MessageID, 10, 64)
	if err != nil || number == 0 || strconv.FormatUint(number, 10) != h.MessageID {
		return ErrSyncML
	}
	for _, field := range []struct {
		name   string
		target *SyncMLLocation
	}{{"Target", &h.Target}, {"Source", &h.Source}} {
		node, err := e.one(syncMLNS, field.name)
		if err != nil {
			return ErrSyncML
		}
		location, err := parseSyncMLLocation(node)
		if err != nil {
			return err
		}
		*field.target = *location
	}
	if node, _ := e.optional(syncMLNS, "Meta"); node != nil {
		meta, err := parseSyncMLMeta(node)
		if err != nil {
			return err
		}
		h.Meta = meta
	}
	if node, _ := e.optional(syncMLNS, "Cred"); node != nil {
		if !syncMLFields(node, "Meta", "Data") || len(node.Children) != 2 {
			return ErrSyncML
		}
		metaNode, err := node.one(syncMLNS, "Meta")
		if err != nil {
			return ErrSyncML
		}
		meta, err := parseSyncMLMeta(metaNode)
		if err != nil || !syncMLAuthenticationMeta(meta, false) {
			return ErrSyncML
		}
		value, err := syncMLField(node, "Data", 24, true)
		decoded, decodeErr := base64.StdEncoding.Strict().DecodeString(value)
		defer clear(decoded)
		if err != nil || decodeErr != nil || len(decoded) != 16 || base64.StdEncoding.EncodeToString(decoded) != value {
			return ErrSyncML
		}
		h.Credential = &SyncMLCredential{Digest: value}
	}
	return nil
}

func parseSyncMLMeta(e *xmlElement) (*SyncMLMeta, error) {
	if len(e.Attrs) != 0 || !e.container() {
		return nil, ErrSyncML
	}
	// MetInf may be wrapped explicitly or its children may appear directly.
	if len(e.Children) == 1 && e.Children[0].is(syncMLMetaNS, "MetInf") {
		e = e.Children[0]
		if len(e.Attrs) != 0 || !e.container() {
			return nil, ErrSyncML
		}
	}
	m := &SyncMLMeta{}
	seen := map[string]bool{}
	for _, child := range e.Children {
		name := child.Name.Local
		if child.Name.Space != syncMLMetaNS || (seen[name] && name != "EMI") {
			return nil, ErrSyncML
		}
		seen[name] = true
		value, err := syncMLText(child, 1024, false)
		if err != nil {
			return nil, err
		}
		switch name {
		case "Format":
			m.Format = value
		case "Type":
			m.Type = value
		case "Mark":
			m.Mark = value
		case "Version":
			m.Version = value
		case "NextNonce":
			m.NextNonce = value
		case "EMI":
			if len(m.EMI) >= 16 {
				return nil, ErrSyncML
			}
			m.EMI = append(m.EMI, value)
		case "Size", "MaxMsgSize", "MaxObjSize":
			number, err := strconv.ParseUint(value, 10, 32)
			if err != nil || strconv.FormatUint(number, 10) != value || (name != "Size" && number == 0) {
				return nil, ErrSyncML
			}
			switch name {
			case "Size":
				m.Size = &number
			case "MaxMsgSize":
				m.MaxMessageSize = &number
			case "MaxObjSize":
				m.MaxObjectSize = &number
			}
		default:
			return nil, ErrSyncML
		}
	}
	return m, nil
}

func syncMLAuthenticationMeta(m *SyncMLMeta, challenge bool) bool {
	if m == nil || m.Type != syncMLDigestType || m.Format != "b64" || m.Mark != "" || m.Version != "" || m.Size != nil || m.MaxMessageSize != nil || m.MaxObjectSize != nil || len(m.EMI) != 0 {
		return false
	}
	if !challenge {
		return m.NextNonce == ""
	}
	nonce, err := decodeSyncMLNonce(m.NextNonce)
	clear(nonce)
	return err == nil
}

func parseSyncMLData(e *xmlElement) (*SyncMLData, error) {
	if len(e.content) > MaxSyncMLDataBytes || len(e.Text) > MaxSyncMLDataBytes || len(e.Attrs) > 1 {
		return nil, ErrSyncML
	}
	data := &SyncMLData{}
	if len(e.Attrs) == 1 {
		attr := e.Attrs[0]
		if attr.Name != (xml.Name{Space: syncMLMicrosoftNS, Local: "originalerror"}) || len(attr.Value) != 10 || !strings.HasPrefix(attr.Value, "0x") {
			return nil, ErrSyncML
		}
		if _, err := strconv.ParseUint(attr.Value[2:], 16, 32); err != nil {
			return nil, ErrSyncML
		}
		data.OriginalError = attr.Value
	}
	if len(e.Children) == 0 {
		data.Text = e.Text
		return data, nil
	}
	// MS-MDM allows namespace-qualified markup. Reparse without the envelope's
	// namespace context and require identical expanded names. This prevents a
	// detached payload from changing meaning when it is persisted or encoded.
	wrapped := append([]byte("<data>"), e.content...)
	wrapped = append(wrapped, []byte("</data>")...)
	standalone, err := parseXML(wrapped, MaxSyncMLDataBytes+13)
	if err != nil || !sameSyncMLMarkup(e, standalone) {
		return nil, ErrSyncML
	}
	data.XML = string(e.content)
	return data, nil
}

func sameSyncMLMarkup(a, b *xmlElement) bool {
	if a.Text != b.Text || len(a.Children) != len(b.Children) {
		return false
	}
	for i, child := range a.Children {
		other := b.Children[i]
		if child.Name != other.Name || len(child.Attrs) != len(other.Attrs) {
			return false
		}
		for j, attr := range child.Attrs {
			if attr != other.Attrs[j] {
				return false
			}
		}
		if !sameSyncMLMarkup(child, other) {
			return false
		}
	}
	return true
}

type syncMLParser struct {
	ids        map[string]bool
	items      int
	references int
}

func (p *syncMLParser) item(e *xmlElement) (*SyncMLItem, error) {
	p.items++
	if p.items > MaxSyncMLItems || !syncMLFields(e, "Target", "Source", "Meta", "Data", "MoreData") {
		return nil, ErrSyncML
	}
	i := &SyncMLItem{}
	for _, child := range e.Children {
		switch child.Name.Local {
		case "Target", "Source":
			location, err := parseSyncMLLocation(child)
			if err != nil {
				return nil, err
			}
			if child.Name.Local == "Target" {
				i.Target = location
			} else {
				i.Source = location
			}
		case "Meta":
			meta, err := parseSyncMLMeta(child)
			if err != nil {
				return nil, err
			}
			i.Meta = meta
		case "Data":
			data, err := parseSyncMLData(child)
			if err != nil {
				return nil, err
			}
			i.Data = data
		case "MoreData":
			if !syncMLEmpty(child) {
				return nil, ErrSyncML
			}
			i.MoreData = true
		}
	}
	if i.MoreData && i.Data == nil {
		return nil, ErrSyncML
	}
	return i, nil
}

func (p *syncMLParser) command(e *xmlElement, depth int) (*SyncMLCommand, error) {
	if depth > 8 || e.Name.Space != syncMLNS {
		return nil, ErrSyncML
	}
	kind := e.Name.Local
	allowed := []string{"CmdID"}
	switch kind {
	case "Add", "Replace", "Delete", "Get":
		allowed = append(allowed, "Meta", "Item*")
	case "Exec":
		allowed = append(allowed, "Meta", "Item*")
	case "Alert":
		allowed = append(allowed, "Data", "Item*")
	case "Results":
		allowed = append(allowed, "MsgRef", "CmdRef", "Meta", "TargetRef", "SourceRef", "Item*")
	case "Status":
		allowed = append(allowed, "MsgRef", "CmdRef", "Cmd", "TargetRef*", "SourceRef*", "Chal", "Data", "Item*")
	case "Atomic", "Sequence":
		allowed = append(allowed, "Meta", "Add*", "Replace*", "Delete*", "Get*", "Exec*", "Atomic*", "Alert*")
		if kind == "Atomic" {
			allowed = append(allowed, "Sequence*")
		}
	default:
		return nil, ErrSyncML
	}
	if !syncMLFields(e, allowed...) {
		return nil, ErrSyncML
	}
	id, err := syncMLField(e, "CmdID", 64, true)
	if err != nil || id == "0" || p.ids[id] || len(p.ids) >= MaxSyncMLCommands {
		return nil, ErrSyncML
	}
	p.ids[id] = true
	c := &SyncMLCommand{Kind: kind, ID: id}
	for _, child := range e.Children {
		switch child.Name.Local {
		case "CmdID":
		case "MsgRef", "CmdRef", "Cmd", "TargetRef", "SourceRef":
			maximum := 64
			if child.Name.Local == "TargetRef" || child.Name.Local == "SourceRef" {
				maximum = 2048
				p.references++
				if p.references > MaxSyncMLReferences {
					return nil, ErrSyncML
				}
			}
			value, err := syncMLText(child, maximum, child.Name.Local == "CmdRef")
			if err != nil {
				return nil, err
			}
			switch child.Name.Local {
			case "MsgRef":
				c.MessageRef = value
			case "CmdRef":
				c.CommandRef = value
			case "Cmd":
				c.CommandName = value
			case "TargetRef":
				c.TargetRefs = append(c.TargetRefs, value)
			case "SourceRef":
				c.SourceRefs = append(c.SourceRefs, value)
			}
		case "Meta":
			meta, err := parseSyncMLMeta(child)
			if err != nil {
				return nil, err
			}
			c.Meta = meta
		case "Chal":
			if !syncMLFields(child, "Meta") || len(child.Children) != 1 {
				return nil, ErrSyncML
			}
			meta, err := parseSyncMLMeta(child.Children[0])
			if err != nil || !syncMLAuthenticationMeta(meta, true) {
				return nil, ErrSyncML
			}
			c.Challenge = meta
		case "Data":
			data, err := parseSyncMLData(child)
			if err != nil {
				return nil, err
			}
			c.Data = data
		case "Item":
			item, err := p.item(child)
			if err != nil {
				return nil, err
			}
			c.Items = append(c.Items, *item)
		default:
			command, err := p.command(child, depth+1)
			if err != nil {
				return nil, err
			}
			c.Commands = append(c.Commands, *command)
		}
	}
	if kind == "Status" || kind == "Results" {
		if c.MessageRef == "" {
			return nil, ErrSyncML
		}
		number, err := strconv.ParseUint(c.MessageRef, 10, 64)
		if err != nil || strconv.FormatUint(number, 10) != c.MessageRef {
			return nil, ErrSyncML
		}
		if ref, _ := e.optional(syncMLNS, "CmdRef"); ref == nil && (kind != "Status" || c.CommandName != "SyncHdr") {
			return nil, ErrSyncML
		}
	}
	if kind == "Status" || kind == "Alert" {
		if c.Data == nil || c.Data.XML != "" {
			return nil, ErrSyncML
		}
		code, err := strconv.ParseUint(c.Data.Text, 10, 16)
		if err != nil || strconv.FormatUint(code, 10) != c.Data.Text {
			return nil, ErrSyncML
		}
		if kind == "Status" && (c.CommandName == "" || code < 100 || code > 999) {
			return nil, ErrSyncML
		}
		if kind == "Alert" && (code < 1000 || code > 1999 || c.Data.OriginalError != "") {
			return nil, ErrSyncML
		}
	}
	if kind == "Atomic" || kind == "Sequence" {
		if len(c.Commands) == 0 {
			return nil, ErrSyncML
		}
	} else if kind != "Status" && kind != "Alert" && len(c.Items) == 0 {
		return nil, ErrSyncML
	}
	if kind == "Exec" && len(c.Items) != 1 {
		return nil, ErrSyncML
	}
	return c, nil
}

// Kept local to the codec so untrusted XML strings never reach an external fetch
// or an XML parser with entity expansion enabled.
func syncMLMarkupValid(value string) bool {
	if value == "" || len(value) > MaxSyncMLDataBytes {
		return false
	}
	wrapped := bytes.Join([][]byte{[]byte("<data>"), []byte(value), []byte("</data>")}, nil)
	root, err := parseXML(wrapped, MaxSyncMLDataBytes+13)
	return err == nil && len(root.Children) != 0
}
