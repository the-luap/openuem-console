package apple

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Declaration struct {
	Type        string         `json:"Type"`
	Identifier  string         `json:"Identifier"`
	ServerToken string         `json:"ServerToken"`
	Payload     map[string]any `json:"Payload"`
}

type DeclarationItem struct {
	Identifier  string `json:"Identifier"`
	ServerToken string `json:"ServerToken"`
}
type DeclarationItems struct {
	Activations    []DeclarationItem `json:"Activations"`
	Configurations []DeclarationItem `json:"Configurations"`
	Assets         []DeclarationItem `json:"Assets"`
	Management     []DeclarationItem `json:"Management"`
}
type DeclarationManifest struct {
	Declarations      DeclarationItems `json:"Declarations"`
	DeclarationsToken string           `json:"DeclarationsToken"`
}

var versionPattern = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]{1,3})?$`)

func ValidateUpdatePolicy(d Device, p UpdatePolicy) error {
	if d.Status != "enrolled" {
		return errors.New("device must be enrolled")
	}
	capabilities := d.Capabilities()
	if !capabilities.SpecificOSUpdate || capabilities.UpdateReason != "" {
		return errors.New(capabilities.UpdateReason)
	}
	if !versionPattern.MatchString(p.TargetVersion) {
		return errors.New("enter an OS version such as 18.7.1")
	}
	if CompareVersions(p.TargetVersion, d.OSVersion) < 0 {
		return errors.New("the operating system cannot be downgraded through an update policy")
	}
	if len(p.TargetBuild) > 32 || strings.ContainsAny(p.TargetBuild, " /\r\n\t") {
		return errors.New("invalid target build")
	}
	if _, err := time.Parse("2006-01-02T15:04:05", p.Deadline); err != nil {
		return errors.New("deadline must use YYYY-MM-DDTHH:MM:SS in the device's local time, without an offset")
	}
	if p.DetailsURL != "" {
		u, err := url.Parse(p.DetailsURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return errors.New("update details must use an HTTPS URL")
		}
	}
	return nil
}

// CompareVersions compares numeric OS versions rather than lexicographic strings.
func CompareVersions(a, b string) int {
	x, y := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		var n, m int
		if i < len(x) {
			n, _ = strconv.Atoi(x[i])
		}
		if i < len(y) {
			m, _ = strconv.Atoi(y[i])
		}
		if n < m {
			return -1
		}
		if n > m {
			return 1
		}
	}
	return 0
}

func declaration(kind, id string, payload map[string]any) Declaration {
	d := Declaration{Type: kind, Identifier: id, Payload: payload}
	// The token covers the entire declaration except the token itself, and has no
	// random data or timestamps: identical state always has identical tokens.
	b, _ := json.Marshal(d)
	d.ServerToken = digest(b)
	return d
}

func Declarations(d Device, policy *UpdatePolicy) []Declaration {
	if !d.Capabilities().DeclarativeManagement {
		return []Declaration{}
	}
	prefix := "eu.openuem.apple." + d.ID
	names := []string{"device.operating-system.version", "device.operating-system.build-version", "management.declarations"}
	if d.Capabilities().SpecificOSUpdate {
		names = append(names, "softwareupdate.install-state", "softwareupdate.failure-reason", "softwareupdate.pending-version")
	}
	if (d.Family() == PlatformMacOS && CompareVersions(d.OSVersion, "15.0") >= 0 && d.Supervised && d.SupervisedReported) || ((d.Family() == PlatformIOS || d.Family() == PlatformIPadOS) && CompareVersions(d.OSVersion, "18.0") >= 0) {
		names = append(names, "softwareupdate.device-id")
	}
	subscriptions := []map[string]string{}
	for _, name := range names {
		subscriptions = append(subscriptions, map[string]string{"Name": name})
	}
	sub := declaration("com.apple.configuration.management.status-subscriptions", prefix+".status", map[string]any{"StatusItems": subscriptions})
	result := []Declaration{sub}
	configs := []string{sub.Identifier}
	if policy != nil && policy.Status != "unavailable" && d.Capabilities().SpecificOSUpdate && d.Capabilities().UpdateReason == "" {
		payload := map[string]any{"TargetOSVersion": policy.TargetVersion, "TargetLocalDateTime": policy.Deadline}
		if policy.TargetBuild != "" {
			payload["TargetBuildVersion"] = policy.TargetBuild
		}
		if policy.DetailsURL != "" {
			payload["DetailsURL"] = policy.DetailsURL
		}
		update := declaration("com.apple.configuration.softwareupdate.enforcement.specific", prefix+".update", payload)
		result = append(result, update)
		configs = append(configs, update.Identifier)
	}
	return append(result, declaration("com.apple.activation.simple", prefix+".activation", map[string]any{"StandardConfigurations": configs}))
}

func Manifest(declarations []Declaration) DeclarationManifest {
	m := DeclarationManifest{Declarations: DeclarationItems{Activations: []DeclarationItem{}, Configurations: []DeclarationItem{}, Assets: []DeclarationItem{}, Management: []DeclarationItem{}}}
	for _, d := range declarations {
		i := DeclarationItem{d.Identifier, d.ServerToken}
		switch {
		case strings.HasPrefix(d.Type, "com.apple.activation."):
			m.Declarations.Activations = append(m.Declarations.Activations, i)
		case strings.HasPrefix(d.Type, "com.apple.configuration."):
			m.Declarations.Configurations = append(m.Declarations.Configurations, i)
		case strings.HasPrefix(d.Type, "com.apple.asset."):
			m.Declarations.Assets = append(m.Declarations.Assets, i)
		case strings.HasPrefix(d.Type, "com.apple.management."):
			m.Declarations.Management = append(m.Declarations.Management, i)
		}
	}
	b, _ := json.Marshal(m.Declarations)
	m.DeclarationsToken = digest(b)
	return m
}

func Tokens(declarations []Declaration) map[string]any {
	return map[string]any{"SyncTokens": map[string]string{"DeclarationsToken": Manifest(declarations).DeclarationsToken}}
}

func DeclarationResponse(declarations []Declaration, endpoint string) (any, error) {
	switch endpoint {
	case "tokens":
		return Tokens(declarations), nil
	case "declaration-items":
		return Manifest(declarations), nil
	}
	parts := strings.Split(endpoint, "/")
	if len(parts) != 3 || parts[0] != "declaration" {
		return nil, ErrNotFound
	}
	for _, d := range declarations {
		if d.Identifier == parts[2] && strings.HasPrefix(d.Type, "com.apple."+parts[1]+".") {
			return d, nil
		}
	}
	return nil, ErrNotFound
}

type StatusReport struct {
	StatusItems map[string]any   `json:"StatusItems"`
	Errors      []map[string]any `json:"Errors"`
	FullReport  bool             `json:"FullReport"`
}

func ParseStatus(data []byte) (*StatusReport, error) {
	var r StatusReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("invalid DDM status JSON: %w", err)
	}
	if r.StatusItems == nil {
		return nil, errors.New("DDM status requires StatusItems")
	}
	return &r, nil
}

// MergeStatus preserves untouched status keys on incremental reports. Explicit
// null values remove a status key. Full reports replace the previous snapshot.
func MergeStatus(old map[string]any, report StatusReport) map[string]any {
	result := map[string]any{}
	if !report.FullReport {
		for k, v := range old {
			result[k] = v
		}
	}
	for k, v := range report.StatusItems {
		if v == nil {
			delete(result, k)
			continue
		}
		child, ok := v.(map[string]any)
		prev, _ := result[k].(map[string]any)
		if ok {
			result[k] = MergeStatus(prev, StatusReport{StatusItems: child, FullReport: report.FullReport})
		} else {
			if array, isArray := v.([]any); isArray && !report.FullReport {
				previous, _ := result[k].([]any)
				result[k] = mergeStatusArray(previous, array)
			} else {
				result[k] = v
			}
		}
	}
	return result
}

func mergeStatusArray(old, updates []any) []any {
	// Dictionary-valued status arrays use a stable identifier and may carry
	// Apple's _removed marker. Scalar arrays are complete values.
	byID := map[string]any{}
	order := []string{}
	for _, v := range old {
		m, ok := v.(map[string]any)
		if !ok {
			return updates
		}
		id := stringValue(m, "identifier")
		if id == "" {
			return updates
		}
		byID[id] = v
		order = append(order, id)
	}
	for _, v := range updates {
		m, ok := v.(map[string]any)
		if !ok {
			return updates
		}
		id := stringValue(m, "identifier")
		if id == "" {
			return updates
		}
		if removed, _ := m["_removed"].(bool); removed {
			delete(byID, id)
			continue
		}
		if _, exists := byID[id]; !exists {
			order = append(order, id)
		}
		byID[id] = v
	}
	result := []any{}
	emitted := map[string]bool{}
	for _, id := range order {
		if v, ok := byID[id]; ok && !emitted[id] {
			result = append(result, v)
			emitted[id] = true
		}
	}
	return result
}

func statusString(items map[string]any, path ...string) string {
	// Apple encodes status item names as nested dictionaries.
	var value any = items
	for _, part := range path {
		m, ok := value.(map[string]any)
		if !ok {
			return ""
		}
		value = m[part]
	}
	v, _ := value.(string)
	return v
}

func UpdateCompliance(d Device, p UpdatePolicy, now time.Time) string {
	if d.Status != "enrolled" {
		return "not_managed"
	}
	if !d.InventoryFresh(now) {
		return "unknown"
	}
	if !versionPattern.MatchString(d.OSVersion) {
		return "unknown"
	}
	cmp := CompareVersions(d.OSVersion, p.TargetVersion)
	if cmp > 0 || (cmp == 0 && (p.TargetBuild == "" || d.BuildVersion == p.TargetBuild)) {
		return "compliant"
	}
	if p.Status == "failed" {
		return "failed"
	}
	return "update_required"
}
