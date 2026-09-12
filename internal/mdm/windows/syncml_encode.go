package windows

import (
	"bytes"
	"encoding/xml"
	"strconv"
	"unicode/utf8"
)

type syncMLWireElement struct {
	XMLName  xml.Name
	Attrs    []xml.Attr          `xml:",any,attr"`
	Text     string              `xml:",chardata"`
	Raw      string              `xml:",innerxml"`
	Children []syncMLWireElement `xml:",any"`
}

// EncodeElement without an XMLName field preserves the enclosing default
// namespace for local SyncML names. encoding/xml's generic XMLName handling
// would otherwise insert xmlns="" on those children and detach the header/body.
func (e syncMLWireElement) MarshalXML(encoder *xml.Encoder, start xml.StartElement) error {
	if !validSyncMLXMLText(e.Text) {
		return ErrSyncML
	}
	for _, attr := range e.Attrs {
		if !validSyncMLXMLText(attr.Value) {
			return ErrSyncML
		}
	}
	start.Name, start.Attr = e.XMLName, e.Attrs
	content := struct {
		Text     string              `xml:",chardata"`
		Raw      string              `xml:",innerxml"`
		Children []syncMLWireElement `xml:",any"`
	}{e.Text, e.Raw, e.Children}
	return encoder.EncodeElement(content, start)
}

func validSyncMLXMLText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if !(r == '\t' || r == '\n' || r == '\r' || r >= 0x20 && r <= 0xd7ff || r >= 0xe000 && r <= 0xfffd || r >= 0x10000 && r <= 0x10ffff) {
			return false
		}
	}
	return true
}

func syncMLWire(name, text string) syncMLWireElement {
	return syncMLWireElement{XMLName: xml.Name{Local: name}, Text: text}
}

type syncMLBuffer struct{ bytes.Buffer }

func (b *syncMLBuffer) Write(data []byte) (int, error) {
	if len(data) > MaxSyncMLBytes-b.Len() {
		return 0, ErrSyncML
	}
	return b.Buffer.Write(data)
}

// EncodeSyncML emits escaped XML and validates the complete wire document before
// returning any bytes. Callers must separately authorize the session, commands,
// destination and negotiated message/object sizes before delivery.
func EncodeSyncML(message *SyncMLMessage) ([]byte, error) {
	if message == nil {
		return nil, ErrSyncML
	}
	h := message.Header
	if h.Meta != nil && len(h.Meta.EMI) > 16 {
		return nil, ErrSyncML
	}
	header := syncMLWire("SyncHdr", "")
	header.Children = []syncMLWireElement{
		syncMLWire("VerDTD", "1.2"), syncMLWire("VerProto", "DM/1.2"),
		syncMLWire("SessionID", h.SessionID), syncMLWire("MsgID", h.MessageID),
		syncMLLocationWire("Target", &h.Target), syncMLLocationWire("Source", &h.Source),
	}
	if h.ResponseURI != "" {
		header.Children = append(header.Children, syncMLWire("RespURI", h.ResponseURI))
	}
	if h.Credential != nil {
		credential := syncMLWire("Cred", "")
		credential.Children = []syncMLWireElement{syncMLMetaWire(&SyncMLMeta{Format: "b64", Type: syncMLDigestType}), syncMLWire("Data", h.Credential.Digest)}
		header.Children = append(header.Children, credential)
	}
	if h.Meta != nil {
		header.Children = append(header.Children, syncMLMetaWire(h.Meta))
	}
	body := syncMLWire("SyncBody", "")
	budget := syncMLWireBudget{}
	for _, command := range message.Commands {
		element, err := budget.command(command, 0)
		if err != nil {
			return nil, err
		}
		body.Children = append(body.Children, element)
	}
	if message.Final {
		body.Children = append(body.Children, syncMLWire("Final", ""))
	}
	root := syncMLWire("SyncML", "")
	root.XMLName.Space = syncMLNS
	root.Children = []syncMLWireElement{header, body}
	buffer := &syncMLBuffer{}
	encoder := xml.NewEncoder(buffer)
	if err := encoder.Encode(root); err != nil {
		return nil, ErrSyncML
	}
	if err := encoder.Close(); err != nil {
		return nil, ErrSyncML
	}
	data := buffer.Bytes()
	if _, err := ParseSyncML(data); err != nil {
		clear(data)
		return nil, ErrSyncML
	}
	return data, nil
}

func syncMLLocationWire(name string, location *SyncMLLocation) syncMLWireElement {
	e := syncMLWire(name, "")
	e.Children = []syncMLWireElement{syncMLWire("LocURI", location.URI)}
	if location.Name != "" {
		e.Children = append(e.Children, syncMLWire("LocName", location.Name))
	}
	return e
}

func syncMLMetaWire(meta *SyncMLMeta) syncMLWireElement {
	e := syncMLWire("Meta", "")
	appendValue := func(name, value string) {
		if value == "" {
			return
		}
		child := syncMLWire(name, value)
		child.XMLName.Space = syncMLMetaNS
		e.Children = append(e.Children, child)
	}
	appendValue("Format", meta.Format)
	appendValue("Type", meta.Type)
	appendValue("Mark", meta.Mark)
	if meta.Size != nil {
		appendValue("Size", strconv.FormatUint(*meta.Size, 10))
	}
	appendValue("Version", meta.Version)
	appendValue("NextNonce", meta.NextNonce)
	if meta.MaxMessageSize != nil {
		appendValue("MaxMsgSize", strconv.FormatUint(*meta.MaxMessageSize, 10))
	}
	if meta.MaxObjectSize != nil {
		appendValue("MaxObjSize", strconv.FormatUint(*meta.MaxObjectSize, 10))
	}
	for _, value := range meta.EMI {
		child := syncMLWire("EMI", value)
		child.XMLName.Space = syncMLMetaNS
		e.Children = append(e.Children, child)
	}
	return e
}

func syncMLDataWire(data *SyncMLData) (syncMLWireElement, error) {
	e := syncMLWire("Data", data.Text)
	if len(data.Text) > MaxSyncMLDataBytes || len(data.XML) > MaxSyncMLDataBytes || (data.XML != "" && (data.Text != "" || !syncMLMarkupValid(data.XML))) {
		return e, ErrSyncML
	}
	e.Raw = data.XML
	if data.OriginalError != "" {
		e.Attrs = []xml.Attr{{Name: xml.Name{Space: syncMLMicrosoftNS, Local: "originalerror"}, Value: data.OriginalError}}
	}
	return e, nil
}

type syncMLWireBudget struct{ commands, items, references int }

func (b *syncMLWireBudget) command(command SyncMLCommand, depth int) (syncMLWireElement, error) {
	e := syncMLWire(command.Kind, "")
	switch command.Kind {
	case "Add", "Replace", "Delete", "Get", "Exec", "Alert", "Results", "Status", "Atomic", "Sequence":
	default:
		return e, ErrSyncML
	}
	b.commands++
	b.references += len(command.TargetRefs) + len(command.SourceRefs)
	if depth > 8 || b.commands > MaxSyncMLCommands || b.references > MaxSyncMLReferences || (command.Meta != nil && len(command.Meta.EMI) > 16) || (command.Challenge != nil && len(command.Challenge.EMI) > 16) {
		return e, ErrSyncML
	}
	e.Children = []syncMLWireElement{syncMLWire("CmdID", command.ID)}
	if command.MessageRef != "" {
		e.Children = append(e.Children, syncMLWire("MsgRef", command.MessageRef))
	}
	if command.CommandRef != "" || command.Kind == "Results" || (command.Kind == "Status" && command.CommandName != "SyncHdr") {
		e.Children = append(e.Children, syncMLWire("CmdRef", command.CommandRef))
	}
	if command.CommandName != "" {
		e.Children = append(e.Children, syncMLWire("Cmd", command.CommandName))
	}
	if command.Meta != nil {
		e.Children = append(e.Children, syncMLMetaWire(command.Meta))
	}
	for _, ref := range command.TargetRefs {
		e.Children = append(e.Children, syncMLWire("TargetRef", ref))
	}
	for _, ref := range command.SourceRefs {
		e.Children = append(e.Children, syncMLWire("SourceRef", ref))
	}

	if command.Challenge != nil {
		challenge := syncMLWire("Chal", "")
		challenge.Children = []syncMLWireElement{syncMLMetaWire(command.Challenge)}
		e.Children = append(e.Children, challenge)
	}
	if command.Data != nil {
		data, err := syncMLDataWire(command.Data)
		if err != nil {
			return e, err
		}
		e.Children = append(e.Children, data)
	}
	for _, item := range command.Items {
		b.items++
		if b.items > MaxSyncMLItems || (item.Meta != nil && len(item.Meta.EMI) > 16) {
			return e, ErrSyncML
		}
		node := syncMLWire("Item", "")
		if item.Target != nil {
			node.Children = append(node.Children, syncMLLocationWire("Target", item.Target))
		}
		if item.Source != nil {
			node.Children = append(node.Children, syncMLLocationWire("Source", item.Source))
		}
		if item.Meta != nil {
			node.Children = append(node.Children, syncMLMetaWire(item.Meta))
		}
		if item.Data != nil {
			data, err := syncMLDataWire(item.Data)
			if err != nil {
				return e, err
			}
			node.Children = append(node.Children, data)
		}
		if item.MoreData {
			node.Children = append(node.Children, syncMLWire("MoreData", ""))
		}
		e.Children = append(e.Children, node)
	}
	for _, child := range command.Commands {
		node, err := b.command(child, depth+1)
		if err != nil {
			return e, err
		}
		e.Children = append(e.Children, node)
	}
	return e, nil
}
