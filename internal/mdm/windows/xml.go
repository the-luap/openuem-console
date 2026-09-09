// Package windows implements the native Windows device management protocols.
// Enrollment authorization and management identities are separate from the
// OpenUEM agent transport and from untrusted discovery device hints.
package windows

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

var ErrXML = errors.New("invalid or oversized Windows management XML")

var xmlDeclaration = regexp.MustCompile(`^version[\t\r\n ]*=[\t\r\n ]*(?:"1\.0"|'1\.0')(?:[\t\r\n ]+encoding[\t\r\n ]*=[\t\r\n ]*(?:"(?i:utf-8)"|'(?i:utf-8)'))?(?:[\t\r\n ]+standalone[\t\r\n ]*=[\t\r\n ]*(?:"(?:yes|no)"|'(?:yes|no)'))?[\t\r\n ]*$`)

// XML 1.0 NameStartChar without a colon. RawToken validates the full XML Name,
// but does not validate the start of the local part after a namespace prefix.
var xmlNameStart = regexp.MustCompile(`^[A-Z_a-z\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}]`)

const (
	soapNS       = "http://www.w3.org/2003/05/soap-envelope"
	addressingNS = "http://www.w3.org/2005/08/addressing"
	xmlNS        = "http://www.w3.org/XML/1998/namespace"
	xmlnsNS      = "http://www.w3.org/2000/xmlns/"
	xsiNS        = "http://www.w3.org/2001/XMLSchema-instance"
)

type xmlElement struct {
	Name     xml.Name
	Attrs    []xml.Attr
	Children []*xmlElement
	Text     string
	content  []byte
}

type xmlFrame struct {
	element      *xmlElement
	rawName      xml.Name
	ns           map[string]string
	text         strings.Builder
	contentStart int64
}

// Resolve namespaces explicitly because encoding/xml.Token accepts undeclared
// prefixes. Duplicate expanded attributes and mismatched raw end tags must not
// acquire a different meaning in a downstream SOAP implementation.
func parseXML(data []byte, maximum int) (*xmlElement, error) {
	if maximum < 1 || len(data) == 0 || len(data) > maximum || !utf8.Valid(data) {
		return nil, ErrXML
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	decoder := xml.NewDecoder(bytes.NewReader(data))
	stack := []*xmlFrame{}
	var root *xmlElement
	nodes, declarations := 0, 0
	for {
		offset := decoder.InputOffset()
		token, err := decoder.RawToken()
		if err == io.EOF {
			if root == nil || len(stack) != 0 {
				return nil, ErrXML
			}
			return root, nil
		}
		if err != nil {
			return nil, ErrXML
		}
		switch token := token.(type) {
		case xml.StartElement:
			nodes++
			if nodes > 4096 || len(stack) >= 32 || len(token.Attr) > 32 || len(stack) == 0 && root != nil {
				return nil, ErrXML
			}
			ns := map[string]string{"xml": xmlNS}
			if len(stack) > 0 {
				for prefix, uri := range stack[len(stack)-1].ns {
					ns[prefix] = uri
				}
			}
			declared := map[string]bool{}
			for _, attr := range token.Attr {
				if attr.Name.Space != "xmlns" && attr.Name != (xml.Name{Local: "xmlns"}) {
					continue
				}
				prefix := attr.Name.Local
				if attr.Name.Space == "" {
					prefix = ""
				}
				if declared[prefix] || prefix == "xmlns" || attr.Value == xmlnsNS ||
					prefix == "xml" && attr.Value != xmlNS || prefix != "xml" && attr.Value == xmlNS ||
					prefix != "" && (attr.Value == "" || !xmlNameStart.MatchString(prefix)) || strings.Contains(prefix, ":") {
					return nil, ErrXML
				}
				declared[prefix] = true
				ns[prefix] = attr.Value
			}
			if len(ns) > 64 {
				return nil, ErrXML
			}
			name, ok := expandedName(token.Name, ns, true)
			if !ok {
				return nil, ErrXML
			}
			element := &xmlElement{Name: name}
			attributes := map[xml.Name]bool{}
			for _, attr := range token.Attr {
				if attr.Name.Space == "xmlns" || attr.Name == (xml.Name{Local: "xmlns"}) {
					continue
				}
				name, ok := expandedName(attr.Name, ns, false)
				if !ok || attributes[name] {
					return nil, ErrXML
				}
				attributes[name] = true
				element.Attrs = append(element.Attrs, xml.Attr{Name: name, Value: attr.Value})
			}
			if len(stack) == 0 {
				root = element
			} else {
				parent := stack[len(stack)-1].element
				parent.Children = append(parent.Children, element)
			}
			stack = append(stack, &xmlFrame{element: element, rawName: token.Name, ns: ns, contentStart: decoder.InputOffset()})
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1].rawName != token.Name {
				return nil, ErrXML
			}
			frame := stack[len(stack)-1]
			frame.element.Text = frame.text.String()
			frame.element.content = data[frame.contentStart:offset]
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				// Outside the root, only literal XML whitespace is legal. A
				// whitespace entity or CDATA section is still document content.
				if !xmlWhitespace(string(data[offset:decoder.InputOffset()])) {
					return nil, ErrXML
				}
			} else {
				stack[len(stack)-1].text.Write(token)
			}
		case xml.ProcInst:
			if token.Target != "xml" || offset != 0 || root != nil || declarations != 0 || !xmlDeclaration.Match(token.Inst) {
				return nil, ErrXML
			}
			declarations++
		case xml.Directive:
			return nil, ErrXML
		case xml.Comment:
		default:
			return nil, ErrXML
		}
	}
}

func expandedName(raw xml.Name, ns map[string]string, element bool) (xml.Name, bool) {
	if !xmlNameStart.MatchString(raw.Local) || strings.Contains(raw.Local, ":") || raw.Space == "xmlns" {
		return xml.Name{}, false
	}
	if raw.Space == "" && !element {
		return raw, true
	}
	uri, exists := ns[raw.Space]
	if raw.Space != "" && !exists {
		return xml.Name{}, false
	}
	return xml.Name{Space: uri, Local: raw.Local}, true
}

func (e *xmlElement) is(namespace, local string) bool {
	return e != nil && e.Name == (xml.Name{Space: namespace, Local: local})
}

// one also rejects namespace lookalikes and duplicates of a known field.
func (e *xmlElement) one(namespace, local string) (*xmlElement, error) {
	found, err := e.optional(namespace, local)
	if err != nil || found == nil {
		return nil, ErrXML
	}
	return found, nil
}

func (e *xmlElement) optional(namespace, local string) (*xmlElement, error) {
	var found *xmlElement
	for _, child := range e.Children {
		if child.Name.Local != local {
			continue
		}
		if found != nil || child.Name.Space != namespace {
			return nil, ErrXML
		}
		found = child
	}
	return found, nil
}

func xmlWhitespace(text string) bool { return strings.Trim(text, "\t\r\n ") == "" }

func (e *xmlElement) container() bool { return xmlWhitespace(e.Text) }

func (e *xmlElement) plainText(maximum int) (string, error) {
	if len(e.Children) != 0 || len(e.Attrs) != 0 || len(e.Text) > maximum {
		return "", ErrXML
	}
	return strings.TrimSpace(e.Text), nil
}
