package apple

import (
	"encoding/asn1"
	"errors"
	"fmt"

	"howett.net/plist"
)

const MaxPKCS12Bytes = 256 << 10

var errPKCS12Envelope = errors.New("provide a DER-encoded PKCS12 version 3 archive with a supported content envelope")

// These checks inspect only a bounded DER envelope. They never decrypt an
// archive, derive a password key, verify its MAC/signature or inspect identities.
// In particular, do not pass uploaded bytes to an unbounded PKCS12 decoder:
// attacker-controlled KDF iteration counts and key lengths can exhaust resources.
func pkcs12Value(data []byte) (asn1.RawValue, error) {
	var value asn1.RawValue
	rest, err := asn1.Unmarshal(data, &value)
	if err != nil || len(rest) != 0 {
		return value, errPKCS12Envelope
	}
	return value, nil
}

func pkcs12Sequence(value asn1.RawValue, minimum, maximum int) ([]asn1.RawValue, error) {
	if value.Class != 0 || value.Tag != asn1.TagSequence || !value.IsCompound {
		return nil, errPKCS12Envelope
	}
	values := []asn1.RawValue{}
	data := value.Bytes
	for len(data) > 0 {
		if len(values) == maximum {
			return nil, errPKCS12Envelope
		}
		var child asn1.RawValue
		rest, err := asn1.Unmarshal(data, &child)
		if err != nil || len(rest) >= len(data) {
			return nil, errPKCS12Envelope
		}
		values = append(values, child)
		data = rest
	}
	if len(values) < minimum {
		return nil, errPKCS12Envelope
	}
	return values, nil
}

func pkcs12Content(value asn1.RawValue) (string, asn1.RawValue, error) {
	fields, err := pkcs12Sequence(value, 2, 2)
	if err != nil {
		return "", value, err
	}
	var oid asn1.ObjectIdentifier
	if _, err = asn1.Unmarshal(fields[0].FullBytes, &oid); err != nil || fields[1].Class != 2 || fields[1].Tag != 0 || !fields[1].IsCompound {
		return "", value, errPKCS12Envelope
	}
	inner, err := pkcs12Value(fields[1].Bytes)
	return oid.String(), inner, err
}

func pkcs12Octets(value asn1.RawValue) bool {
	return value.Class == 0 && value.Tag == asn1.TagOctetString && !value.IsCompound && len(value.Bytes) > 0
}

func validatePKCS12Envelope(data []byte) error {
	if len(data) == 0 || len(data) > MaxPKCS12Bytes {
		return errors.New("PKCS12 archives must be non-empty and at most 256 KiB")
	}
	root, err := pkcs12Value(data)
	if err != nil {
		return err
	}
	fields, err := pkcs12Sequence(root, 2, 3)
	if err != nil {
		return err
	}
	var version int
	if _, err = asn1.Unmarshal(fields[0].FullBytes, &version); err != nil || version != 3 {
		return errPKCS12Envelope
	}
	kind, content, err := pkcs12Content(fields[1])
	if err != nil {
		return err
	}
	switch kind {
	case "1.2.840.113549.1.7.1": // Data containing AuthenticatedSafe.
		if !pkcs12Octets(content) {
			return errPKCS12Envelope
		}
		authenticated, err := pkcs12Value(content.Bytes)
		if err != nil {
			return err
		}
		sections, err := pkcs12Sequence(authenticated, 1, 64)
		if err != nil {
			return err
		}
		for _, section := range sections {
			kind, content, err := pkcs12Content(section)
			if err != nil {
				return err
			}
			switch kind {
			case "1.2.840.113549.1.7.1":
				if !pkcs12Octets(content) {
					return errPKCS12Envelope
				}
			case "1.2.840.113549.1.7.3", "1.2.840.113549.1.7.6": // EnvelopedData, EncryptedData.
				if _, err = pkcs12Sequence(content, 1, 16); err != nil {
					return err
				}
			default:
				return errPKCS12Envelope
			}
		}
	case "1.2.840.113549.1.7.2": // SignedData remains opaque; no signature verification.
		if _, err = pkcs12Sequence(content, 1, 16); err != nil {
			return err
		}
	default:
		return errPKCS12Envelope
	}
	if len(fields) == 3 {
		mac, err := pkcs12Sequence(fields[2], 2, 3)
		if err != nil || !pkcs12Octets(mac[1]) {
			return errPKCS12Envelope
		}
		digest, err := pkcs12Sequence(mac[0], 2, 2)
		if err != nil || !pkcs12Octets(digest[1]) {
			return errPKCS12Envelope
		}
		algorithm, err := pkcs12Sequence(digest[0], 1, 2)
		if err != nil {
			return err
		}
		var oid asn1.ObjectIdentifier
		if _, err = asn1.Unmarshal(algorithm[0].FullBytes, &oid); err != nil {
			return errPKCS12Envelope
		}
		if len(mac) == 3 {
			var iterations int64
			if _, err = asn1.Unmarshal(mac[2].FullBytes, &iterations); err != nil || iterations < 1 {
				return errPKCS12Envelope
			}
		}
	}
	return nil
}

func buildPKCS12Payload(payload, settings map[string]any, scope string) error {
	payload["PayloadType"] = "com.apple.security.pkcs12"
	payload["PayloadContent"] = settings["IdentityData"]
	payload["PayloadCertificateFileName"] = "identity.p12"
	for _, key := range []string{"Password", "KeyIsExtractable", "AllowAllAppsAccess"} {
		if value, exists := settings[key]; exists {
			payload[key] = value
		}
	}
	return validatePKCS12Payload(payload, scope, nil)
}

func validatePKCS12Payload(payload map[string]any, scope string, d *Device) error {
	if stringValue(payload, "PayloadType") != "com.apple.security.pkcs12" {
		return nil
	}
	data, ok := payload["PayloadContent"].([]byte)
	if !ok {
		return errors.New("PKCS12 payloads require binary archive data")
	}
	if err := validatePKCS12Envelope(data); err != nil {
		return err
	}
	if value, exists := payload["Password"]; exists && !certificateText(value, 8192, true) {
		return errors.New("PKCS12 password must be bounded text without control characters")
	}
	if value, exists := payload["PayloadCertificateFileName"]; exists && !certificateText(value, 255, false) {
		return errors.New("PKCS12 filename must be bounded text")
	}
	if err := validateCertificateTarget(d, scope, "10.7", "4.0"); err != nil {
		return err
	}
	for _, option := range []struct{ key, minimum string }{{"AllowAllAppsAccess", "10.10"}, {"KeyIsExtractable", "10.15"}} {
		value, exists := payload[option.key]
		if !exists {
			continue
		}
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s must be a boolean", option.key)
		}
		if d != nil && (d.Family() != PlatformMacOS || CompareVersions(d.OSVersion, option.minimum) < 0) {
			return fmt.Errorf("%s requires macOS %s or later; omit this option for iPhone and iPad", option.key, option.minimum)
		}
	}
	return nil
}

func validatePKCS12Profile(p *Profile, d *Device) error {
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		return errors.New("invalid saved PKCS12 profile")
	}
	items, _ := root["PayloadContent"].([]any)
	for _, item := range items {
		payload, _ := item.(map[string]any)
		if err := validatePKCS12Payload(payload, p.Scope, d); err != nil {
			return err
		}
	}
	return nil
}
