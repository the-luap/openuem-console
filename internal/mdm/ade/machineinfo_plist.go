package ade

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const maxMachinePlist = 64 << 10

// MachineInfo is a flat dictionary in Apple's schema. Parse only bounded scalar
// objects, so binary plist reference cycles, nested XML and duplicate dictionary
// keys cannot hide a second identity or cause unbounded decoder recursion.
func parseMachinePlist(data []byte) (*MachineInfo, error) {
	if len(data) == 0 || len(data) > maxMachinePlist {
		return nil, ErrMachineInfo
	}
	var fields map[string]any
	var err error
	if bytes.HasPrefix(data, []byte("bplist00")) {
		fields, err = machineBinaryPlist(data)
	} else {
		fields, err = machineXMLPlist(data)
	}
	if err != nil {
		return nil, ErrMachineInfo
	}
	info := &MachineInfo{}
	for _, field := range []struct {
		name     string
		target   *string
		required bool
		max      int
	}{
		{"UDID", &info.UDID, true, 64}, {"SERIAL", &info.Serial, true, 64},
		{"PRODUCT", &info.Product, true, 128}, {"VERSION", &info.Build, true, 64},
		// OS_VERSION is unavailable before iOS 17 and macOS 14.
		{"OS_VERSION", &info.OSVersion, false, 64}, {"LANGUAGE", &info.Language, false, 64},
	} {
		v, found := fields[field.name]
		if !found && !field.required {
			continue
		}
		s, ok := v.(string)
		if !ok || !opaque(s, field.max) {
			return nil, ErrMachineInfo
		}
		*field.target = s
	}
	if !ValidSerial(info.Serial) {
		return nil, ErrMachineInfo
	}
	for _, c := range info.UDID {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '-') {
			return nil, ErrMachineInfo
		}
	}
	for _, field := range []struct {
		name   string
		target *bool
	}{
		{"MDM_CAN_REQUEST_SOFTWARE_UPDATE", &info.CanRequestSoftwareUpdate},
		{"MDM_CAN_REQUEST_PSSO_CONFIG", &info.CanRequestPSSO},
		{"MANDATORY_SOFTWARE_UPDATE_REQUIRED", &info.MandatorySoftwareUpdate},
	} {
		if v, found := fields[field.name]; found {
			b, ok := v.(bool)
			if !ok {
				return nil, ErrMachineInfo
			}
			*field.target = b
		}
	}
	return info, nil
}

func machineXMLPlist(data []byte) (map[string]any, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	next := func() (xml.Token, error) {
		for {
			t, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch v := t.(type) {
			case xml.CharData:
				if len(bytes.TrimSpace(v)) != 0 {
					return nil, ErrMachineInfo
				}
			case xml.Comment:
			default:
				return t, nil
			}
		}
	}
	var root xml.StartElement
	declaration, doctype := false, false
	for {
		t, err := next()
		if err != nil {
			return nil, ErrMachineInfo
		}
		switch v := t.(type) {
		case xml.ProcInst:
			if v.Target != "xml" || declaration || doctype {
				return nil, ErrMachineInfo
			}
			declaration = true
		case xml.Directive:
			// encoding/xml never fetches or expands external entities. Permit
			// Apple's standard plist DOCTYPE only, without an internal subset.
			if doctype || !strings.HasPrefix(string(v), "DOCTYPE plist ") || bytes.ContainsAny(v, "[]<>") {
				return nil, ErrMachineInfo
			}
			doctype = true
		case xml.StartElement:
			root = v
		default:
			return nil, ErrMachineInfo
		}
		if root.Name.Local != "" {
			break
		}
	}
	if root.Name != (xml.Name{Local: "plist"}) || len(root.Attr) != 1 || root.Attr[0].Name != (xml.Name{Local: "version"}) || root.Attr[0].Value != "1.0" {
		return nil, ErrMachineInfo
	}
	t, err := next()
	dict, ok := t.(xml.StartElement)
	if err != nil || !ok || dict.Name != (xml.Name{Local: "dict"}) || len(dict.Attr) != 0 {
		return nil, ErrMachineInfo
	}
	text := func(start xml.StartElement) (string, error) {
		var value strings.Builder
		for {
			t, err := d.Token()
			if err != nil {
				return "", ErrMachineInfo
			}
			switch v := t.(type) {
			case xml.CharData:
				value.Write(v)
			case xml.EndElement:
				if v.Name != start.Name {
					return "", ErrMachineInfo
				}
				return value.String(), nil
			default:
				return "", ErrMachineInfo
			}
		}
	}
	fields := make(map[string]any)
	for {
		t, err := next()
		if err != nil {
			return nil, ErrMachineInfo
		}
		if end, ok := t.(xml.EndElement); ok && end.Name == dict.Name {
			break
		}
		key, ok := t.(xml.StartElement)
		if !ok || key.Name != (xml.Name{Local: "key"}) || len(key.Attr) != 0 || len(fields) >= 64 {
			return nil, ErrMachineInfo
		}
		name, err := text(key)
		if err != nil || !opaque(name, 128) {
			return nil, ErrMachineInfo
		}
		if _, exists := fields[name]; exists {
			return nil, ErrMachineInfo
		}
		t, err = next()
		start, ok := t.(xml.StartElement)
		if err != nil || !ok || start.Name.Space != "" || len(start.Attr) != 0 {
			return nil, ErrMachineInfo
		}
		value, err := text(start)
		if err != nil {
			return nil, ErrMachineInfo
		}
		switch start.Name.Local {
		case "string":
			fields[name] = value
		case "true", "false":
			if value != "" {
				return nil, ErrMachineInfo
			}
			fields[name] = start.Name.Local == "true"
		case "data":
			value = strings.Map(func(r rune) rune {
				if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
					return -1
				}
				return r
			}, value)
			v, err := base64.StdEncoding.Strict().DecodeString(value)
			if err != nil {
				return nil, ErrMachineInfo
			}
			fields[name] = v
		case "integer":
			v, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil {
				return nil, ErrMachineInfo
			}
			fields[name] = v
		case "real":
			v, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				return nil, ErrMachineInfo
			}
			fields[name] = v
		case "date":
			v, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
			if err != nil {
				return nil, ErrMachineInfo
			}
			fields[name] = v
		default:
			return nil, ErrMachineInfo
		}
	}
	t, err = next()
	end, ok := t.(xml.EndElement)
	if err != nil || !ok || end.Name != root.Name {
		return nil, ErrMachineInfo
	}
	if _, err = next(); err != io.EOF {
		return nil, ErrMachineInfo
	}
	return fields, nil
}

func machineBinaryPlist(data []byte) (map[string]any, error) {
	if len(data) < 40 {
		return nil, ErrMachineInfo
	}
	t := data[len(data)-32:]
	width := func(n byte) bool { return n == 1 || n == 2 || n == 4 || n == 8 }
	if !bytes.Equal(t[:6], make([]byte, 6)) || !width(t[6]) || !width(t[7]) {
		return nil, ErrMachineInfo
	}
	read := func(b []byte) uint64 {
		var v uint64
		for _, x := range b {
			v = v<<8 | uint64(x)
		}
		return v
	}
	count, top, table := read(t[8:16]), read(t[16:24]), read(t[24:32])
	if count == 0 || count > 129 || top >= count || table < 8 || table >= uint64(len(data)-32) || count*uint64(t[6]) != uint64(len(data)-32)-table {
		return nil, ErrMachineInfo
	}
	offsets := make([]int, count)
	for i := range offsets {
		o := read(data[int(table)+i*int(t[6]) : int(table)+(i+1)*int(t[6])])
		if o < 8 || o >= table {
			return nil, ErrMachineInfo
		}
		offsets[i] = int(o)
	}
	sorted := append([]int(nil), offsets...)
	sort.Ints(sorted)
	ends := make(map[int]int, count)
	for i, o := range sorted {
		end := int(table)
		if i+1 < len(sorted) {
			end = sorted[i+1]
		}
		if end <= o {
			return nil, ErrMachineInfo
		}
		ends[o] = end
	}
	object := func(ref uint64) (byte, uint64, []byte, error) {
		if ref >= count {
			return 0, 0, nil, ErrMachineInfo
		}
		o := offsets[ref]
		b := data[o:ends[o]]
		tag := b[0]
		b = b[1:]
		n := uint64(tag & 15)
		if n == 15 && (tag>>4 == 4 || tag>>4 == 5 || tag>>4 == 6 || tag>>4 == 13) {
			if len(b) < 2 || b[0]>>4 != 1 || b[0]&15 > 3 {
				return 0, 0, nil, ErrMachineInfo
			}
			w := 1 << (b[0] & 15)
			if w > len(b)-1 {
				return 0, 0, nil, ErrMachineInfo
			}
			n, b = read(b[1:1+w]), b[1+w:]
		}
		return tag, n, b, nil
	}
	scalar := func(ref uint64) (any, error) {
		tag, n, b, err := object(ref)
		if err != nil {
			return nil, err
		}
		switch tag >> 4 {
		case 0:
			if (tag != 8 && tag != 9) || len(b) != 0 {
				return nil, ErrMachineInfo
			}
			return tag == 9, nil
		case 1:
			if n > 3 || len(b) != 1<<n {
				return nil, ErrMachineInfo
			}
			return read(b), nil
		case 2, 3:
			if tag>>4 == 3 && tag != 0x33 || n != 2 && n != 3 || len(b) != 1<<n {
				return nil, ErrMachineInfo
			}
			v := math.Float64frombits(read(b))
			if n == 2 {
				v = float64(math.Float32frombits(uint32(read(b))))
			}
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil, ErrMachineInfo
			}
			// Dates are opaque scalar metadata here; no identity field accepts
			// a date/number in place of a string or boolean.
			return v, nil
		case 4, 5:
			if n != uint64(len(b)) {
				return nil, ErrMachineInfo
			}
			if tag>>4 == 4 {
				return b, nil
			}
			for _, c := range b {
				if c > 127 {
					return nil, ErrMachineInfo
				}
			}
			return string(b), nil
		case 6:
			if n > uint64(len(b))/2 || 2*n != uint64(len(b)) {
				return nil, ErrMachineInfo
			}
			units := make([]uint16, n)
			for i := range units {
				units[i] = binary.BigEndian.Uint16(b[i*2 : i*2+2])
			}
			for i := 0; i < len(units); i++ {
				if !utf16.IsSurrogate(rune(units[i])) {
					continue
				}
				if i+1 == len(units) || utf16.DecodeRune(rune(units[i]), rune(units[i+1])) == utf8.RuneError {
					return nil, ErrMachineInfo
				}
				i++
			}
			return string(utf16.Decode(units)), nil
		}
		return nil, ErrMachineInfo
	}
	tag, n, refs, err := object(top)
	if err != nil || tag>>4 != 13 || n > 64 || 2*n*uint64(t[7]) != uint64(len(refs)) {
		return nil, ErrMachineInfo
	}
	fields := make(map[string]any)
	ref := func(i uint64) uint64 { return read(refs[i*uint64(t[7]) : (i+1)*uint64(t[7])]) }
	for i := uint64(0); i < n; i++ {
		key, err := scalar(ref(i))
		name, ok := key.(string)
		if err != nil || !ok || !opaque(name, 128) {
			return nil, ErrMachineInfo
		}
		if _, exists := fields[name]; exists {
			return nil, ErrMachineInfo
		}
		v, err := scalar(ref(i + n))
		if err != nil {
			return nil, ErrMachineInfo
		}
		fields[name] = v
	}
	return fields, nil
}
