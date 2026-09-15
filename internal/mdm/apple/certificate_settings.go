package apple

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

func certificateInteger(value any) (uint64, bool) {
	switch n := value.(type) {
	case int:
		if n >= 0 {
			return uint64(n), true
		}
	case int64:
		if n >= 0 {
			return uint64(n), true
		}
	case int32:
		if n >= 0 {
			return uint64(n), true
		}
	case uint:
		return uint64(n), true
	case uint64:
		return n, true
	case uint32:
		return uint64(n), true
	}
	return 0, false
}

func certificateText(value any, maximum int, empty bool) bool {
	text, ok := value.(string)
	if !ok || len(text) > maximum || !utf8.ValidString(text) || !empty && strings.TrimSpace(text) == "" {
		return false
	}
	for _, r := range text {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func certificateURL(raw string, httpsOnly bool) (*url.URL, error) {
	value, err := url.Parse(raw)
	if err != nil || !certificateText(raw, 2048, false) || value.Hostname() == "" || value.User != nil || value.Fragment != "" || value.Scheme != "https" && (httpsOnly || value.Scheme != "http") {
		return nil, errors.New("enter an HTTP or HTTPS certificate server URL without credentials or a fragment")
	}
	if port := value.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid certificate server port")
		}
	}
	return value, nil
}

func certificateOID(value string, aliases bool) bool {
	if aliases {
		switch value {
		case "C", "L", "ST", "O", "OU", "CN":
			return true
		}
	}
	if len(value) > 128 {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 32 {
		return false
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		n, err := strconv.ParseUint(part, 10, 31)
		if err != nil || strconv.FormatUint(n, 10) != part {
			return false
		}
		oid[i] = int(n)
	}
	_, err := asn1.Marshal(oid)
	return err == nil
}

func certificateSubjectLines(raw string) ([]any, error) {
	if len(raw) > 16384 {
		return nil, errors.New("certificate subjects support at most 16 KiB")
	}
	result := []any{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 || !certificateOID(strings.TrimSpace(pair[0]), true) || !certificateText(pair[1], 1024, false) {
			return nil, errors.New("enter one subject attribute=value per line using C, L, ST, O, OU, CN or a numeric OID")
		}
		result = append(result, []any{[]any{strings.TrimSpace(pair[0]), pair[1]}})
	}
	if len(result) > 64 {
		return nil, errors.New("certificate subjects support at most 64 relative names")
	}
	return result, nil
}

func validateCertificateSubject(raw any) error {
	rdns, ok := raw.([]any)
	if !ok || len(rdns) > 64 {
		return errors.New("certificate subjects must contain at most 64 relative names")
	}
	for _, rawRDN := range rdns {
		rdn, ok := rawRDN.([]any)
		if !ok || len(rdn) == 0 || len(rdn) > 16 {
			return errors.New("each certificate relative name requires 1 to 16 attributes")
		}
		for _, rawPair := range rdn {
			pair, ok := rawPair.([]any)
			if !ok || len(pair) != 2 {
				return errors.New("certificate subject attributes must be OID/value pairs")
			}
			oid, ok := pair[0].(string)
			if !ok || !certificateOID(oid, true) || !certificateText(pair[1], 1024, false) {
				return errors.New("invalid certificate subject attribute")
			}
		}
	}
	return nil
}

func certificateNameLines(raw string) ([]any, error) {
	if len(raw) > 16384 {
		return nil, errors.New("certificate name lists support at most 16 KiB")
	}
	result := []any{}
	for _, line := range strings.Split(raw, "\n") {
		value := strings.TrimSpace(line)
		if value == "" {
			continue
		}
		if !certificateText(value, 1024, false) {
			return nil, errors.New("certificate names must be bounded text")
		}
		result = append(result, value)
	}
	if len(result) > 64 {
		return nil, errors.New("certificate name lists support at most 64 values")
	}
	return result, nil
}

func validateCertificateNames(raw any, arrays bool) error {
	names, ok := raw.(map[string]any)
	if !ok || len(names) > 4 {
		return errors.New("invalid certificate alternative-name dictionary")
	}
	for key, value := range names {
		switch key {
		case "rfc822Name", "dNSName", "uniformResourceIdentifier", "ntPrincipalName":
		default:
			return errors.New("unsupported certificate alternative-name type")
		}
		if text, ok := value.(string); ok {
			if !certificateText(text, 1024, false) {
				return errors.New("invalid certificate alternative name")
			}
			continue
		}
		values, ok := value.([]any)
		if !arrays || !ok || len(values) > 64 {
			return errors.New("certificate alternative names must be strings or bounded string arrays")
		}
		for _, v := range values {
			if !certificateText(v, 1024, false) {
				return errors.New("invalid certificate alternative name")
			}
		}
	}
	return nil
}

func validateCertificateTarget(d *Device, scope, macMinimum, phoneMinimum string) error {
	if scope != "System" && scope != "User" {
		return errors.New("certificate scope must be System or User")
	}
	if d == nil {
		return nil
	}
	minimum := phoneMinimum
	switch d.Family() {
	case PlatformMacOS:
		minimum = macMinimum
	case PlatformIOS, PlatformIPadOS:
		if scope == "User" {
			return errors.New("User certificate profiles require a managed Mac user channel")
		}
	default:
		return errors.New("refresh inventory to identify the certificate target platform")
	}
	if !versionPattern.MatchString(d.OSVersion) || CompareVersions(d.OSVersion, minimum) < 0 {
		return fmt.Errorf("this certificate profile requires %s %s or later", d.Family(), minimum)
	}
	return nil
}
