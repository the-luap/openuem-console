package apple

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"howett.net/plist"
)

const MaxPublicCertificateBytes = 256 << 10

// Public certificate imports never accept a private key or an identity archive.
// PEM bundles are split into individual DER certificate payloads by the editor.
func parsePublicCertificates(data []byte, pemOnly bool) ([]*x509.Certificate, error) {
	if len(data) == 0 || len(data) > MaxPublicCertificateBytes {
		return nil, errors.New("public certificates must be non-empty and at most 256 KiB")
	}
	trimmed := bytes.TrimSpace(data)
	certificates := []*x509.Certificate{}
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN")) || pemOnly {
		for len(trimmed) > 0 {
			if !bytes.HasPrefix(trimmed, []byte("-----BEGIN CERTIFICATE-----")) {
				return nil, errors.New("PEM imports must contain only certificate blocks and whitespace")
			}
			block, rest := pem.Decode(trimmed)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return nil, errors.New("invalid public certificate PEM block")
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.New("invalid X.509 certificate")
			}
			certificates = append(certificates, certificate)
			trimmed = bytes.TrimSpace(rest)
			if len(certificates) > 16 {
				return nil, errors.New("import at most 16 public certificates per profile")
			}
		}
	} else {
		var err error
		certificates, err = x509.ParseCertificates(data)
		if err != nil {
			return nil, errors.New("provide public certificates in PEM or DER format")
		}
	}
	if len(certificates) == 0 || len(certificates) > 16 {
		return nil, errors.New("import 1 to 16 public certificates per profile")
	}
	return certificates, nil
}

func buildPublicCertificatePayload(payload, settings map[string]any, scope string) ([]any, error) {
	if scope != "System" && scope != "User" {
		return nil, errors.New("select System or User certificate scope")
	}
	data, ok := settings["CertificateData"].([]byte)
	if !ok {
		return nil, errors.New("select a public certificate file")
	}
	certificates, err := parsePublicCertificates(data, false)
	if err != nil {
		return nil, err
	}
	base := stringValue(payload, "PayloadIdentifier")
	additional := []any{}
	seen := map[string]bool{}
	for _, certificate := range certificates {
		if seen[string(certificate.Raw)] {
			continue
		}
		seen[string(certificate.Raw)] = true
		current := payload
		if len(seen) > 1 {
			current = map[string]any{"PayloadType": "com.apple.security.pkcs1", "PayloadIdentifier": base + "." + strconv.Itoa(len(seen)), "PayloadUUID": uuid.NewString(), "PayloadVersion": 1, "PayloadDisplayName": payload["PayloadDisplayName"]}
			additional = append(additional, current)
		}
		current["PayloadType"] = "com.apple.security.pkcs1"
		current["PayloadContent"] = certificate.Raw
		current["PayloadCertificateFileName"] = "certificate-" + strconv.Itoa(len(seen)) + ".cer"
	}
	return additional, nil
}

func validatePublicCertificatePayload(payload map[string]any, scope string, d *Device) error {
	kind := stringValue(payload, "PayloadType")
	if kind != "com.apple.security.root" && kind != "com.apple.security.pkcs1" && kind != "com.apple.security.pem" {
		return nil
	}
	if scope != "System" && scope != "User" {
		return errors.New("public certificate scope must be System or User")
	}
	data, ok := payload["PayloadContent"].([]byte)
	if !ok {
		return errors.New("public certificate payloads require binary certificate data")
	}
	var certificates []*x509.Certificate
	if kind == "com.apple.security.pem" {
		var err error
		certificates, err = parsePublicCertificates(data, true)
		if err != nil {
			return err
		}
	} else {
		if len(data) == 0 || len(data) > MaxPublicCertificateBytes {
			return errors.New("invalid public certificate size")
		}
		certificate, err := x509.ParseCertificate(data)
		if err != nil {
			return errors.New("this certificate payload requires one DER-encoded X.509 certificate")
		}
		certificates = []*x509.Certificate{certificate}
	}
	if value, exists := payload["PayloadCertificateFileName"]; exists {
		name, ok := value.(string)
		if !ok || !validMacAppText(name, 255) {
			return errors.New("certificate filename must be bounded text")
		}
	}
	if d == nil {
		return nil
	}
	minimum := "4.0"
	switch d.Family() {
	case PlatformMacOS:
		minimum = "10.7"
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
	now := time.Now()
	for _, certificate := range certificates {
		if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return errors.New("the certificate is not currently valid; review its validity dates before assignment")
		}
	}
	return nil
}

func validatePublicCertificateProfile(p *Profile, d *Device) error {
	var root map[string]any
	if _, err := plist.Unmarshal(p.Payload, &root); err != nil {
		return errors.New("invalid saved public certificate profile")
	}
	items, _ := root["PayloadContent"].([]any)
	for _, item := range items {
		payload, _ := item.(map[string]any)
		if err := validatePublicCertificatePayload(payload, p.Scope, d); err != nil {
			return err
		}
	}
	return nil
}
