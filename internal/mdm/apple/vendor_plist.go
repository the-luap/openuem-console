package apple

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
)

// The signed portal format has exactly three string values. Parse that grammar
// directly so duplicate keys, nested values, namespaces and ignored extensions
// cannot be interpreted differently by the verifier and Apple's portal.
func parseVendorPlist(data []byte) (map[string]string, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	var root xml.StartElement
	declaration, doctype := false, false
	for {
		token, err := d.Token()
		if err != nil {
			return nil, ErrVendorRequest
		}
		switch t := token.(type) {
		case xml.ProcInst:
			if t.Target != "xml" || declaration || doctype {
				return nil, ErrVendorRequest
			}
			declaration = true
		case xml.Directive:
			if doctype || strings.Join(strings.Fields(string(t)), " ") != `DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"` {
				return nil, ErrVendorRequest
			}
			doctype = true
		case xml.Comment:
		case xml.CharData:
			if len(bytes.TrimSpace(t)) != 0 {
				return nil, ErrVendorRequest
			}
		case xml.StartElement:
			root = t
		default:
			return nil, ErrVendorRequest
		}
		if root.Name.Local != "" {
			break
		}
	}
	if root.Name.Space != "" || root.Name.Local != "plist" || len(root.Attr) != 1 || root.Attr[0].Name.Space != "" || root.Attr[0].Name.Local != "version" || root.Attr[0].Value != "1.0" {
		return nil, ErrVendorRequest
	}
	if err := vendorXMLStart(d, "dict"); err != nil {
		return nil, err
	}
	fields := make(map[string]string)
	for {
		token, err := vendorXMLToken(d)
		if err != nil {
			return nil, err
		}
		if end, ok := token.(xml.EndElement); ok {
			if end.Name.Space != "" || end.Name.Local != "dict" {
				return nil, ErrVendorRequest
			}
			break
		}
		start, ok := token.(xml.StartElement)
		if !ok || !vendorXMLElement(start, "key") {
			return nil, ErrVendorRequest
		}
		key, err := vendorXMLText(d, start)
		if err != nil {
			return nil, err
		}
		switch key {
		case "PushCertRequestCSR", "PushCertCertificateChain", "PushCertSignature":
		default:
			return nil, ErrVendorRequest
		}
		if _, exists := fields[key]; exists {
			return nil, ErrVendorRequest
		}
		token, err = vendorXMLToken(d)
		if err != nil {
			return nil, err
		}
		start, ok = token.(xml.StartElement)
		if !ok || !vendorXMLElement(start, "string") {
			return nil, ErrVendorRequest
		}
		value, err := vendorXMLText(d, start)
		if err != nil || value == "" {
			return nil, ErrVendorRequest
		}
		fields[key] = value
	}
	if len(fields) != 3 {
		return nil, ErrVendorRequest
	}
	token, err := vendorXMLToken(d)
	end, ok := token.(xml.EndElement)
	if err != nil || !ok || end.Name != root.Name {
		return nil, ErrVendorRequest
	}
	if _, err = vendorXMLToken(d); err != io.EOF {
		return nil, ErrVendorRequest
	}
	return fields, nil
}

func vendorXMLElement(start xml.StartElement, name string) bool {
	return start.Name.Space == "" && start.Name.Local == name && len(start.Attr) == 0
}

func vendorXMLStart(d *xml.Decoder, name string) error {
	token, err := vendorXMLToken(d)
	start, ok := token.(xml.StartElement)
	if err != nil || !ok || !vendorXMLElement(start, name) {
		return ErrVendorRequest
	}
	return nil
}

func vendorXMLToken(d *xml.Decoder) (xml.Token, error) {
	for {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		switch t := token.(type) {
		case xml.CharData:
			if len(bytes.TrimSpace(t)) != 0 {
				return nil, ErrVendorRequest
			}
		case xml.Comment:
		default:
			return token, nil
		}
	}
}

func vendorXMLText(d *xml.Decoder, start xml.StartElement) (string, error) {
	var text strings.Builder
	for {
		token, err := d.Token()
		if err != nil {
			return "", ErrVendorRequest
		}
		switch t := token.(type) {
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			if t.Name != start.Name {
				return "", ErrVendorRequest
			}
			return text.String(), nil
		default:
			return "", ErrVendorRequest
		}
	}
}
