package apple

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

var ErrWindowsSoftware = errors.New("invalid approved Windows package definition")

// WindowsSoftwareInput is approval intent, never a page model. Source URLs and
// executable arguments may contain credentials and are encrypted together.
type WindowsSoftwareInput struct {
	Name, Identifier, Version, Kind, Architecture, MinimumOS, SHA256 string
	Detection                                                        WindowsSoftwareDetection
	SuccessCodes, RebootCodes                                        []uint32
	Execution                                                        WindowsSoftwareExecution `json:"-"`
}

type WindowsSoftwareExecution struct {
	SourceURL          string            `json:"source_url,omitempty"`
	InstallArguments   []string          `json:"install_arguments,omitempty"`
	MSIProperties      map[string]string `json:"msi_properties,omitempty"`
	UninstallURL       string            `json:"uninstall_url,omitempty"`
	UninstallSHA256    string            `json:"uninstall_sha256,omitempty"`
	UninstallArguments []string          `json:"uninstall_arguments,omitempty"`
}

// Detection checks a machine-installed product and an exact reported version.
// Neither command acknowledgement nor a generic inventory match satisfies it.
type WindowsSoftwareDetection struct {
	Kind         string `json:"kind"`
	ProductCode  string `json:"product_code,omitempty"`
	UninstallKey string `json:"uninstall_key,omitempty"`
	RegistryView string `json:"registry_view,omitempty"`
	Version      string `json:"version"`
}

// WindowsSoftwareMetadata is safe for catalog readers. It has no source URL or
// argument/property values. Those are available only to an execution adapter.
type WindowsSoftwareMetadata struct {
	Kind                   string                   `json:"kind"`
	Detection              WindowsSoftwareDetection `json:"detection"`
	SuccessCodes           []uint32                 `json:"success_codes"`
	RebootCodes            []uint32                 `json:"reboot_codes"`
	InstallArgumentCount   int                      `json:"install_argument_count"`
	UninstallArgumentCount int                      `json:"uninstall_argument_count"`
	MSIPropertyNames       []string                 `json:"msi_property_names"`
	UninstallSHA256        string                   `json:"uninstall_sha256,omitempty"`
}

var windowsCatalogIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)
var windowsOSVersion = regexp.MustCompile(`^10\.0\.[1-9][0-9]{3,4}(\.(0|[1-9][0-9]{0,5}))?$`)
var windowsMSIProperty = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

func validWindowsArgument(value string) bool {
	return len(value) <= 2048 && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validWindowsDigest(value string) bool {
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == 32 && value == strings.ToLower(value)
}

func validWindowsSource(value, extension string) bool {
	if !validMacAppText(value, 8192) {
		return false
	}
	for _, c := range value {
		if c <= 32 || c > 126 {
			return false
		}
	}
	u, err := url.ParseRequestURI(value)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Hostname() == "" || strings.HasSuffix(u.Host, ":") || strings.Contains(value, "#") || strings.HasSuffix(u.Path, "/") || !strings.HasSuffix(strings.ToLower(u.Path), extension) {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}

func validWindowsPackageCoordinate(identifier, version string) bool {
	valid := func(value string) bool {
		return utf8.ValidString(value) && utf8.RuneCountInString(value) <= 128 && !strings.HasPrefix(value, "-") && strings.TrimSpace(value) == value && strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) || strings.ContainsRune(`\/:*?"<>|`, r) }) < 0
	}
	if identifier == "" || version == "" || !valid(identifier) || !valid(version) || strings.IndexFunc(identifier, unicode.IsSpace) >= 0 {
		return false
	}
	parts := strings.Split(identifier, ".")
	if len(parts) < 2 || len(parts) > 8 {
		return false
	}
	for _, part := range parts {
		if n := utf8.RuneCountInString(part); n < 1 || n > 32 {
			return false
		}
	}
	return true
}

func (d WindowsSoftwareDetection) Validate() error {
	if !validMacAppText(d.Version, 128) {
		return ErrWindowsSoftware
	}
	switch d.Kind {
	case "msi-product":
		id, err := uuid.Parse(strings.TrimSuffix(strings.TrimPrefix(d.ProductCode, "{"), "}"))
		if err != nil || id == uuid.Nil || d.ProductCode != "{"+strings.ToUpper(id.String())+"}" || d.UninstallKey != "" || d.RegistryView != "" {
			return ErrWindowsSoftware
		}
	case "uninstall-key":
		if !validMacAppText(d.UninstallKey, 255) || strings.ContainsAny(d.UninstallKey, `\/`) || d.ProductCode != "" || (d.RegistryView != "32" && d.RegistryView != "64") {
			return ErrWindowsSoftware
		}
	default:
		return ErrWindowsSoftware
	}
	return nil
}

func (p WindowsSoftwareInput) Validate() error {
	if !validMacAppText(p.Name, 255) || !validMacAppText(p.Version, 128) || !windowsOSVersion.MatchString(p.MinimumOS) || (p.Architecture != "x86_64" && p.Architecture != "arm64" && p.Architecture != "x86") || p.Detection.Validate() != nil {
		return ErrWindowsSoftware
	}
	if len(p.SuccessCodes) == 0 || len(p.SuccessCodes) > 16 || len(p.RebootCodes) > 16 || !slices.Contains(p.SuccessCodes, uint32(0)) {
		return ErrWindowsSoftware
	}
	seen := map[uint32]bool{}
	for _, codes := range [][]uint32{p.SuccessCodes, p.RebootCodes} {
		for _, code := range codes {
			if seen[code] {
				return ErrWindowsSoftware
			}
			seen[code] = true
		}
	}
	e := p.Execution
	if len(e.InstallArguments) > 32 || len(e.UninstallArguments) > 32 || len(e.MSIProperties) > 32 {
		return ErrWindowsSoftware
	}
	for _, args := range [][]string{e.InstallArguments, e.UninstallArguments} {
		for _, arg := range args {
			if !validWindowsArgument(arg) {
				return ErrWindowsSoftware
			}
		}
	}
	for name, value := range e.MSIProperties {
		// Restart, scope, logging and external transforms remain adapter-owned.
		if !windowsMSIProperty.MatchString(name) || !validWindowsArgument(value) || slices.Contains([]string{"REBOOT", "REBOOTPROMPT", "ALLUSERS", "MSIINSTALLPERUSER", "TRANSFORMS", "PATCH", "ADDLOCAL", "REMOVE", "ACTION", "INSTALL", "UNINSTALL", "TARGETDIR"}, name) {
			return ErrWindowsSoftware
		}
	}
	switch p.Kind {
	case "windows-winget":
		if !validWindowsPackageCoordinate(p.Identifier, p.Version) || p.SHA256 != "" || e.SourceURL != "" || len(e.InstallArguments) != 0 || len(e.MSIProperties) != 0 || e.UninstallURL != "" || e.UninstallSHA256 != "" || len(e.UninstallArguments) != 0 || len(p.SuccessCodes) != 1 || len(p.RebootCodes) != 0 {
			return ErrWindowsSoftware
		}
	case "windows-msi":
		if !windowsCatalogIdentifier.MatchString(p.Identifier) || !validWindowsDigest(p.SHA256) || !validWindowsSource(e.SourceURL, ".msi") || p.Detection.Kind != "msi-product" || len(e.InstallArguments) != 0 || len(e.UninstallArguments) != 0 || e.UninstallURL != "" || e.UninstallSHA256 != "" || !slices.Equal(p.SuccessCodes, []uint32{0}) || !slices.Equal(p.RebootCodes, []uint32{3010}) {
			return ErrWindowsSoftware
		}
	case "windows-exe":
		if !windowsCatalogIdentifier.MatchString(p.Identifier) || !validWindowsDigest(p.SHA256) || !validWindowsSource(e.SourceURL, ".exe") || !validWindowsDigest(e.UninstallSHA256) || !validWindowsSource(e.UninstallURL, ".exe") || len(e.MSIProperties) != 0 || len(e.InstallArguments) == 0 || len(e.UninstallArguments) == 0 {
			return ErrWindowsSoftware
		}
	default:
		return ErrWindowsSoftware
	}
	data, err := p.canonical()
	defer clear(data)
	if err != nil || len(data) > 32<<10 {
		return ErrWindowsSoftware
	}
	return nil
}

func (m *WindowsSoftwareMetadata) Scan(value any) error {
	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return ErrWindowsSoftware
	}
	if len(data) > 8192 {
		return ErrWindowsSoftware
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(m) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrWindowsSoftware
	}
	return nil
}

func (p WindowsSoftwareInput) canonical() ([]byte, error) {
	return json.Marshal(struct {
		Input     WindowsSoftwareInput     `json:"input"`
		Execution WindowsSoftwareExecution `json:"execution"`
	}{p, p.Execution})
}

func (p WindowsSoftwareInput) Metadata() WindowsSoftwareMetadata {
	names := make([]string, 0, len(p.Execution.MSIProperties))
	for key := range p.Execution.MSIProperties {
		names = append(names, key)
	}
	slices.Sort(names)
	return WindowsSoftwareMetadata{Kind: p.Kind, Detection: p.Detection, SuccessCodes: slices.Clone(p.SuccessCodes), RebootCodes: slices.Clone(p.RebootCodes), InstallArgumentCount: len(p.Execution.InstallArguments), UninstallArgumentCount: len(p.Execution.UninstallArguments), MSIPropertyNames: names, UninstallSHA256: p.Execution.UninstallSHA256}
}
