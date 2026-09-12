package apple

import (
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrMacApp = errors.New("invalid managed Mac application package or response")

// MacAppPackageInput describes an operator-approved artifact. SourceURL may
// contain a signed download token and must never enter a public page model.
// SingleApp records the publisher's compatibility assertion, not a server-side
// inspection or signature verification of the remote package.
type MacAppPackageInput struct {
	Name, Identifier, Version, Architecture, MinimumOS, SHA256 string
	SourceURL                                                  string `json:"-"`
	SingleApp                                                  bool
}

type MacAppInstallOptions struct {
	RemoveOnUnenroll bool `json:"remove_on_unenroll"`
	TakeOver         bool `json:"take_over"`
}

var macAppIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
var macAppOSPattern = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]{1,3})?$`)

func validMacAppText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == 0xfffe || r == 0xffff {
			return false
		}
	}
	return true
}

func validMacAppIdentifier(value string) bool {
	return len(value) <= 255 && macAppIdentifierPattern.MatchString(value)
}

func (p MacAppPackageInput) Validate() error {
	if !validMacAppText(p.Name, 255) || !validMacAppIdentifier(p.Identifier) || !validMacAppText(p.Version, 128) {
		return ErrMacApp
	}
	if p.Architecture != "universal" && p.Architecture != "arm64" && p.Architecture != "x86_64" {
		return ErrMacApp
	}
	if !macAppOSPattern.MatchString(p.MinimumOS) {
		return ErrMacApp
	}
	major, _ := strconv.Atoi(strings.Split(p.MinimumOS, ".")[0])
	if major < 11 || (!p.SingleApp && major < 14) {
		return ErrMacApp
	}
	hash, err := hex.DecodeString(p.SHA256)
	if err != nil || len(hash) != 32 || p.SHA256 != strings.ToLower(p.SHA256) {
		return ErrMacApp
	}
	if !validMacAppText(p.SourceURL, 8192) {
		return ErrMacApp
	}
	for _, r := range p.SourceURL {
		if r <= 32 || r > 126 {
			return ErrMacApp
		}
	}
	u, err := url.ParseRequestURI(p.SourceURL)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.Hostname() == "" || strings.HasSuffix(u.Host, ":") || u.User != nil || u.Fragment != "" || strings.Contains(p.SourceURL, "#") || u.Path == "" {
		return ErrMacApp
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return ErrMacApp
		}
	}
	return nil
}

// Inline manifests bind the approved digest without fetching an administrator-
// supplied manifest on the server or exposing a new bearer download endpoint.
func macAppInstallArguments(p MacAppPackageInput, options MacAppInstallOptions) (map[string]any, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	args := map[string]any{
		"Manifest": map[string]any{"items": []any{map[string]any{
			"assets":   []any{map[string]any{"kind": "software-package", "url": p.SourceURL, "sha256": p.SHA256}},
			"metadata": map[string]any{"kind": "software", "bundle-identifier": p.Identifier, "bundle-version": p.Version, "title": p.Name},
		}}},
		"InstallAsManaged": true,
	}
	if options.RemoveOnUnenroll {
		args["ManagementFlags"] = 1
	}
	if options.TakeOver {
		args["ChangeManagementState"] = "Managed"
	}
	return args, nil
}

// The observation is deliberately narrower than the raw application inventory.
// Missing identifiers on macOS cannot prove that the requested app is absent.
type macAppObservation struct {
	State   string
	Version string
}

func macAppManagedObservation(value any, identifier string) (macAppObservation, error) {
	items, ok := value.(map[string]any)
	if !ok || len(items) > 4096 || !validMacAppIdentifier(identifier) {
		return macAppObservation{}, ErrMacApp
	}
	item, present := items[identifier]
	if !present {
		return macAppObservation{State: "absent"}, nil
	}
	dict, ok := item.(map[string]any)
	if !ok {
		return macAppObservation{}, ErrMacApp
	}
	status, ok := dict["Status"].(string)
	if !ok {
		return macAppObservation{}, ErrMacApp
	}
	switch status {
	case "Managed":
		return macAppObservation{State: "managed"}, nil
	case "ManagedButUninstalled":
		return macAppObservation{State: "uninstalled"}, nil
	case "Failed", "UserRejected", "UpdateRejected", "ManagementRejected":
		return macAppObservation{State: "failed"}, nil
	case "Queued", "NeedsRedemption", "Redeeming", "Prompting", "PromptingForLogin", "ValidatingPurchase", "PromptingForUpdate", "PromptingForUpdateLogin", "PromptingForManagement", "ValidatingUpdate", "Updating", "Installing":
		return macAppObservation{State: "pending"}, nil
	default:
		// New OS statuses and UserInstalledApp do not establish management.
		return macAppObservation{State: "unknown"}, nil
	}
}

func macAppInstalledObservation(value any, identifier string) (macAppObservation, error) {
	items, ok := value.([]any)
	if !ok || len(items) > 4096 || !validMacAppIdentifier(identifier) {
		return macAppObservation{}, ErrMacApp
	}
	result := macAppObservation{State: "absent"}
	found, ambiguous := false, false
	for _, item := range items {
		dict, ok := item.(map[string]any)
		if !ok {
			return macAppObservation{}, ErrMacApp
		}
		id, ok := dict["Identifier"].(string)
		if !ok || id == "" {
			ambiguous = true
			continue
		}
		if id != identifier {
			continue
		}
		if found {
			return macAppObservation{State: "conflict"}, nil
		}
		found = true
		version, _ := dict["Version"].(string)
		if !validMacAppText(version, 128) {
			result.State = "unknown"
			continue
		}
		result = macAppObservation{State: "installed", Version: version}
		for _, key := range []string{"Installing", "DownloadFailed", "DownloadWaiting", "DownloadPaused", "DownloadCancelled"} {
			if v, exists := dict[key]; exists {
				flag, ok := v.(bool)
				if !ok {
					return macAppObservation{}, ErrMacApp
				}
				if flag {
					result.State = "pending"
				}
			}
		}
	}
	if ambiguous {
		return macAppObservation{State: "unknown"}, nil
	}
	return result, nil
}
