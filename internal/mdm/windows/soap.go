package windows

import (
	"bytes"
	"encoding/xml"
	"errors"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

var (
	ErrSOAP           = errors.New("invalid Windows enrollment SOAP message")
	ErrMustUnderstand = errors.New("unsupported required SOAP header")
	ErrEndpoint       = errors.New("Windows enrollment endpoint does not match the configured service")
)

type soapMessage struct {
	Action, MessageID, To string
	Header, Body          *xmlElement
}

func parseSOAP(data []byte, maximum int, additionalHeaders ...xml.Name) (*soapMessage, error) {
	root, err := parseXML(data, maximum)
	if err != nil {
		return nil, err
	}
	if !root.is(soapNS, "Envelope") || !root.container() || len(root.Attrs) != 0 || len(root.Children) != 2 || !root.Children[0].is(soapNS, "Header") || !root.Children[1].is(soapNS, "Body") {
		return nil, ErrSOAP
	}
	header, body := root.Children[0], root.Children[1]
	if !header.container() || !body.container() || len(header.Attrs) != 0 || len(body.Attrs) != 0 || len(body.Children) != 1 {
		return nil, ErrSOAP
	}
	known := map[xml.Name]bool{}
	for _, key := range []string{"Action", "MessageID", "To", "ReplyTo"} {
		known[xml.Name{Space: addressingNS, Local: key}] = true
	}
	for _, name := range additionalHeaders {
		known[name] = true
	}
	for _, child := range header.Children {
		for name := range known {
			if child.Name.Local == name.Local && child.Name != name {
				return nil, ErrSOAP
			}
		}
		required, err := soapHeaderAttributes(child)
		if err != nil {
			return nil, err
		}
		if required && !known[child.Name] {
			return nil, ErrMustUnderstand
		}
	}
	message := &soapMessage{Header: header, Body: body.Children[0]}
	for name, field := range map[string]*string{"Action": &message.Action, "MessageID": &message.MessageID, "To": &message.To} {
		e, err := header.one(addressingNS, name)
		if err != nil || len(e.Children) != 0 || len(e.Text) > 2048 {
			return nil, ErrSOAP
		}
		*field = strings.TrimSpace(e.Text)
	}
	if !validMessageID(message.MessageID) || message.Action == "" {
		return nil, ErrSOAP
	}
	reply, err := header.optional(addressingNS, "ReplyTo")
	if err != nil {
		return nil, ErrSOAP
	}
	if reply != nil {
		if !reply.container() || len(reply.Children) != 1 {
			return nil, ErrSOAP
		}
		address, err := reply.one(addressingNS, "Address")
		if err != nil {
			return nil, ErrSOAP
		}
		value, err := address.plainText(256)
		if err != nil || value != addressingNS+"/anonymous" {
			return nil, ErrSOAP
		}
	}
	return message, nil
}

func soapHeaderAttributes(element *xmlElement) (bool, error) {
	required := false
	for _, attr := range element.Attrs {
		switch attr.Name {
		case xml.Name{Space: soapNS, Local: "mustUnderstand"}:
			switch attr.Value {
			case "1", "true":
				required = true
			case "0", "false":
			default:
				return false, ErrSOAP
			}
		case xml.Name{Space: soapNS, Local: "role"}:
			if attr.Value != soapNS+"/role/ultimateReceiver" {
				return false, ErrSOAP
			}
		default:
			return false, ErrSOAP
		}
	}
	return required, nil
}

func validMessageID(value string) bool {
	if len(value) > 128 || !strings.HasPrefix(value, "urn:uuid:") {
		return false
	}
	tail := strings.TrimSpace(strings.TrimPrefix(value, "urn:uuid:"))
	id, err := uuid.Parse(tail)
	return err == nil && id != uuid.Nil && strings.EqualFold(tail, id.String())
}

func enrollmentEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || strings.TrimSpace(raw) != raw || u.Scheme != "https" || !validEndpointHost(u.Hostname()) || u.User != nil || u.Opaque != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !strings.HasPrefix(u.Path, "/") || path.Clean(u.Path) != u.Path || u.EscapedPath() != u.Path || strings.Contains(u.Path, `\`) || strings.HasSuffix(u.Host, ":") {
		return nil, ErrEndpoint
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, ErrEndpoint
		}
	}
	if strings.HasPrefix(u.Host, "[") {
		addr, err := netip.ParseAddr(u.Hostname())
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return nil, ErrEndpoint
		}
	}
	return u, nil
}

func validEndpointHost(host string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Zone() == ""
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r != '-' && !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') {
				return false
			}
		}
	}
	return true
}

func sameEnrollmentEndpoint(actual, expected string) bool {
	a, ea := enrollmentEndpoint(actual)
	b, eb := enrollmentEndpoint(expected)
	if ea != nil || eb != nil {
		return false
	}
	port := func(u *url.URL) string {
		if u.Port() == "" {
			return "443"
		}
		return u.Port()
	}
	return strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b) && a.Path == b.Path
}

func soapResponse(action, relatesTo string, body any) ([]byte, error) {
	data, err := xml.Marshal(body)
	if err != nil {
		return nil, ErrSOAP
	}
	var out bytes.Buffer
	out.WriteString(`<s:Envelope xmlns:s="` + soapNS + `" xmlns:a="` + addressingNS + `"><s:Header><a:Action s:mustUnderstand="1">`)
	xml.EscapeText(&out, []byte(action))
	out.WriteString(`</a:Action>`)
	if relatesTo != "" {
		out.WriteString(`<a:RelatesTo>`)
		xml.EscapeText(&out, []byte(relatesTo))
		out.WriteString(`</a:RelatesTo>`)
	}
	out.WriteString(`</s:Header><s:Body>`)
	out.Write(data)
	out.WriteString(`</s:Body></s:Envelope>`)
	return out.Bytes(), nil
}
