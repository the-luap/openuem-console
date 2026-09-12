// Package winget retains exact manifests from the Microsoft community source.
// A source snapshot is evidence for a separate approval, never execution authority.
package winget

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	Repository       = "microsoft/winget-pkgs"
	MaxManifestBytes = 512 << 10
	maxManifestNodes = 16384
)

var (
	ErrCoordinate = errors.New("invalid exact WinGet package coordinate")
	ErrSource     = errors.New("the Microsoft community manifest source is unavailable")
	ErrNotFound   = errors.New("the exact WinGet manifest was not found")
	ErrManifest   = errors.New("invalid or unsupported WinGet manifest snapshot")
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type Coordinate struct {
	Identifier string `json:"identifier"`
	Version    string `json:"version"`
}

func (c Coordinate) Valid() bool {
	validPart := func(s string, maximum int) bool {
		return s != "" && s != "." && s != ".." && !strings.HasPrefix(s, "-") &&
			utf8.ValidString(s) && utf8.RuneCountInString(s) <= maximum && strings.TrimSpace(s) == s &&
			strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || strings.ContainsRune(`\/:*?"<>|`, r) }) < 0
	}
	if !validPart(c.Identifier, 128) || !validPart(c.Version, 128) || strings.IndexFunc(c.Identifier, unicode.IsSpace) >= 0 {
		return false
	}
	parts := strings.Split(c.Identifier, ".")
	if len(parts) < 2 || len(parts) > 8 {
		return false
	}
	for _, part := range parts {
		if !validPart(part, 32) {
			return false
		}
	}
	return true
}

func (c Coordinate) manifestPath(singleton bool) string {
	first, _ := utf8.DecodeRuneInString(c.Identifier)
	name := c.Identifier + ".installer.yaml"
	if singleton {
		name = c.Identifier + ".yaml"
	}
	return "manifests/" + strings.ToLower(string(first)) + "/" + strings.ReplaceAll(c.Identifier, ".", "/") + "/" + c.Version + "/" + name
}

// Snapshot includes the original bytes, so approval and historical verification
// never require a fresh source lookup. SHA256 covers bytes, including comments.
// Commit is the repository's HTTPS source assertion, not a Git signature.
// Content can contain private URLs or switches: encrypt persisted snapshots and
// never use them directly as public page or audit models.
type Snapshot struct {
	Coordinate Coordinate `json:"coordinate"`
	Commit     string     `json:"commit"`
	Path       string     `json:"path"`
	SHA256     string     `json:"sha256"`
	Content    []byte     `json:"content"`
}

func (Snapshot) String() string     { return "[protected WinGet source snapshot]" }
func (s Snapshot) GoString() string { return s.String() }

// Manifest deliberately retains complete nodes, including unknown fields. A
// delivery adapter must validate all behavior it would translate or omit. The
// snapshot parser neither selects an installer nor treats fields as executable.
type Manifest struct {
	Type, SchemaVersion string
	Root                *yaml.Node
	Installers          []*yaml.Node
}

func (Manifest) String() string     { return "[protected WinGet manifest]" }
func (m Manifest) GoString() string { return m.String() }

func (s Snapshot) Inspect() (*Manifest, error) {
	if !s.Coordinate.Valid() || !commitPattern.MatchString(s.Commit) || len(s.Content) == 0 || len(s.Content) > MaxManifestBytes {
		return nil, ErrManifest
	}
	singleton := s.Path == s.Coordinate.manifestPath(true)
	if !singleton && s.Path != s.Coordinate.manifestPath(false) {
		return nil, ErrManifest
	}
	digest := sha256.Sum256(s.Content)
	if s.SHA256 != hex.EncodeToString(digest[:]) {
		return nil, ErrManifest
	}
	decoder := yaml.NewDecoder(bytes.NewReader(s.Content))
	var document, extra yaml.Node
	if decoder.Decode(&document) != nil || decoder.Decode(&extra) != io.EOF || len(document.Content) != 1 {
		return nil, ErrManifest
	}
	root := document.Content[0]
	remaining := maxManifestNodes
	if root.Kind != yaml.MappingNode || !boundedNode(root, 0, &remaining) {
		return nil, ErrManifest
	}
	fields := mapping(root)
	manifestType := scalar(fields["ManifestType"])
	if manifestType != "installer" && manifestType != "singleton" || singleton != (manifestType == "singleton") ||
		scalar(fields["PackageIdentifier"]) != s.Coordinate.Identifier || scalar(fields["PackageVersion"]) != s.Coordinate.Version {
		return nil, ErrManifest
	}
	// Unknown schema versions require an explicit parser/adapter review. Do not
	// silently reinterpret a future major or a guessed intermediate version.
	schema := scalar(fields["ManifestVersion"])
	switch schema {
	case "1.0.0", "1.1.0", "1.2.0", "1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.9.0", "1.10.0", "1.12.0", "1.28.0":
	default:
		return nil, ErrManifest
	}
	installers := fields["Installers"]
	if installers == nil || installers.Kind != yaml.SequenceNode || len(installers.Content) == 0 || len(installers.Content) > 256 {
		return nil, ErrManifest
	}
	for _, installer := range installers.Content {
		if installer.Kind != yaml.MappingNode {
			return nil, ErrManifest
		}
		architecture := scalar(mapping(installer)["Architecture"])
		switch architecture {
		case "x86", "x64", "arm", "arm64", "neutral":
		default:
			return nil, ErrManifest
		}
	}
	return &Manifest{Type: manifestType, SchemaVersion: schema, Root: root, Installers: installers.Content}, nil
}

func boundedNode(n *yaml.Node, depth int, remaining *int) bool {
	(*remaining)--
	if n == nil || depth > 16 || *remaining < 0 || n.Anchor != "" || n.Alias != nil {
		return false
	}
	switch n.Kind {
	case yaml.MappingNode:
		if n.Tag != "!!map" || len(n.Content)%2 != 0 {
			return false
		}
		seen := make(map[string]bool, len(n.Content)/2)
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "" || key.Value == "<<" || seen[key.Value] {
				return false
			}
			seen[key.Value] = true
		}
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			return false
		}
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str", "!!int", "!!float", "!!bool", "!!null", "!!timestamp":
		default:
			return false
		}
	default:
		return false
	}
	for _, child := range n.Content {
		if !boundedNode(child, depth+1, remaining) {
			return false
		}
	}
	return true
}

func mapping(n *yaml.Node) map[string]*yaml.Node {
	fields := make(map[string]*yaml.Node, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		fields[n.Content[i].Value] = n.Content[i+1]
	}
	return fields
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	// Numeric-looking package versions must retain their exact YAML lexeme.
	if n.Tag != "!!str" && n.Tag != "!!int" && n.Tag != "!!float" {
		return ""
	}
	return n.Value
}

type Source struct{ client *http.Client }

func NewSource() *Source {
	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second,
		MaxResponseHeaderBytes: 32 << 10, ResponseHeaderTimeout: 10 * time.Second,
	}
	return &Source{client: &http.Client{Transport: transport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (s *Source) Close() { s.client.CloseIdleConnections() }

// Fetch resolves the source head once, then uses only that immutable commit for
// both supported filenames. It never downloads the package installer.
func (s *Source) Fetch(ctx context.Context, coordinate Coordinate) (*Snapshot, error) {
	if !coordinate.Valid() {
		return nil, ErrCoordinate
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	data, err := s.get(ctx, "https://api.github.com/repos/"+Repository+"/git/ref/heads/master", 32<<10)
	if err != nil {
		return nil, ErrSource
	}
	var ref, object map[string]json.RawMessage
	var name, kind, commit string
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if !uniqueJSON(decoder, 0) || json.Unmarshal(data, &ref) != nil ||
		json.Unmarshal(ref["ref"], &name) != nil || name != "refs/heads/master" ||
		json.Unmarshal(ref["object"], &object) != nil || json.Unmarshal(object["type"], &kind) != nil || kind != "commit" ||
		json.Unmarshal(object["sha"], &commit) != nil || !commitPattern.MatchString(commit) {
		return nil, ErrSource
	}
	return s.FetchAt(ctx, coordinate, commit)
}

func uniqueJSON(decoder *json.Decoder, depth int) bool {
	if depth > 8 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return true
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return false
			}
			seen[name] = true
			if !uniqueJSON(decoder, depth+1) {
				return false
			}
		}
		token, err = decoder.Token()
		return err == nil && token == json.Delim('}')
	case '[':
		for decoder.More() {
			if !uniqueJSON(decoder, depth+1) {
				return false
			}
		}
		token, err = decoder.Token()
		return err == nil && token == json.Delim(']')
	default:
		return false
	}
}

func (s *Source) FetchAt(ctx context.Context, coordinate Coordinate, commit string) (*Snapshot, error) {
	if !coordinate.Valid() || !commitPattern.MatchString(commit) {
		return nil, ErrCoordinate
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	for _, singleton := range []bool{false, true} {
		path := coordinate.manifestPath(singleton)
		u := url.URL{Scheme: "https", Host: "raw.githubusercontent.com", Path: "/" + Repository + "/" + commit + "/" + path}
		data, err := s.get(ctx, u.String(), MaxManifestBytes)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(data)
		snapshot := &Snapshot{Coordinate: coordinate, Commit: commit, Path: path, SHA256: hex.EncodeToString(digest[:]), Content: data}
		if _, err := snapshot.Inspect(); err != nil {
			return nil, err
		}
		return snapshot, nil
	}
	return nil, ErrNotFound
}

func (s *Source) get(ctx context.Context, target string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, ErrSource
	}
	req.Header.Set("Accept", "application/json, text/plain, application/octet-stream")
	if req.URL.Host == "api.github.com" {
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	}
	req.Header.Set("User-Agent", "OpenUEM-WinGet-Manifest/1")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, ErrSource
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK || resp.ContentLength > limit {
		return nil, ErrSource
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		return nil, ErrSource
	}
	return data, nil
}
