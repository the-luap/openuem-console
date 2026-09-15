package winget

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const fixtureCommit = "0123456789abcdef0123456789abcdef01234567"

var fixtureCoordinate = Coordinate{Identifier: "Example.Editor", Version: "1.20.0"}

const fixtureManifest = `# An owned synthetic manifest; no endpoint or installer is contacted.
PackageIdentifier: Example.Editor
PackageVersion: 1.20.0
InstallerType: wix
Scope: machine
UnknownFutureBehavior:
  MustRemainVisible: true
Installers:
- Architecture: x64
  InstallerUrl: https://example.invalid/editor.msi?private=fixture
  InstallerSha256: 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
  ProductCode: '{90000000-0000-4000-8000-000000000001}'
- Architecture: arm64
  InstallerUrl: https://example.invalid/editor-arm64.msi
ManifestType: installer
ManifestVersion: 1.12.0
`

func fixtureSnapshot(content string) Snapshot {
	data := []byte(content)
	digest := sha256.Sum256(data)
	return Snapshot{Coordinate: fixtureCoordinate, Commit: fixtureCommit, Path: fixtureCoordinate.manifestPath(false), SHA256: hex.EncodeToString(digest[:]), Content: data}
}

func TestSnapshotPreservesExactEvidence(t *testing.T) {
	snapshot := fixtureSnapshot(fixtureManifest)
	manifest, err := snapshot.Inspect()
	if err != nil || manifest.Type != "installer" || manifest.SchemaVersion != "1.12.0" || len(manifest.Installers) != 2 {
		t.Fatalf("manifest inspection: %v", err)
	}
	if scalar(mapping(manifest.Root)["Scope"]) != "machine" || mapping(manifest.Root)["UnknownFutureBehavior"] == nil || scalar(mapping(manifest.Installers[0])["InstallerUrl"]) != "https://example.invalid/editor.msi?private=fixture" {
		t.Fatal("source behavior or private values silently discarded")
	}
	// Parsed views are disposable. Mutating one cannot alter retained raw evidence
	// or a subsequent approval adapter's fresh inspection.
	manifest.Installers[0].Content = nil
	second, err := snapshot.Inspect()
	if err != nil || len(second.Installers[0].Content) == 0 {
		t.Fatal("parsed view mutated snapshot")
	}
	wire, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var restored Snapshot
	if json.Unmarshal(wire, &restored) != nil {
		t.Fatal("snapshot persistence")
	}
	if _, err = restored.Inspect(); err != nil || string(restored.Content) != fixtureManifest {
		t.Fatal("snapshot did not survive exact persistence")
	}
	changed := fixtureSnapshot(fixtureManifest + "# later source comment\n")
	if changed.SHA256 == snapshot.SHA256 {
		t.Fatal("source bytes not bound")
	}
	for _, version := range []string{"1.0", "0123", "2026.09", "1.0 beta", "true", "2026-03-05"} {
		quoted, _ := json.Marshal(version)
		content := strings.Replace(fixtureManifest, "PackageVersion: 1.20.0", "PackageVersion: "+string(quoted), 1)
		s := fixtureSnapshot(content)
		s.Coordinate.Version = version
		s.Path = s.Coordinate.manifestPath(false)
		if _, err := s.Inspect(); err != nil {
			t.Fatalf("exact quoted version %q: %v", version, err)
		}
	}
	for _, version := range []string{"1.0", "0123", "2026.09"} {
		s := fixtureSnapshot(strings.Replace(fixtureManifest, "PackageVersion: 1.20.0", "PackageVersion: "+version, 1))
		s.Coordinate.Version = version
		s.Path = s.Coordinate.manifestPath(false)
		if _, err := s.Inspect(); err != nil {
			t.Fatalf("numeric-looking version %q changed: %v", version, err)
		}
	}
}

func TestSnapshotRejectsChangedBindings(t *testing.T) {
	for name, change := range map[string]func(*Snapshot){
		"content":            func(s *Snapshot) { s.Content[0] = '!' },
		"digest":             func(s *Snapshot) { s.SHA256 = strings.Repeat("0", 64) },
		"uppercase digest":   func(s *Snapshot) { s.SHA256 = strings.ToUpper(s.SHA256) },
		"commit":             func(s *Snapshot) { s.Commit = "master" },
		"short commit":       func(s *Snapshot) { s.Commit = fixtureCommit[:12] },
		"uppercase commit":   func(s *Snapshot) { s.Commit = strings.ToUpper(fixtureCommit) },
		"foreign source":     func(s *Snapshot) { s.Path = "https://foreign.invalid/" + s.Path },
		"path traversal":     func(s *Snapshot) { s.Path = "../" + s.Path },
		"alternate filename": func(s *Snapshot) { s.Path = s.Coordinate.manifestPath(true) },
		"coordinate case": func(s *Snapshot) {
			s.Coordinate.Identifier = "example.Editor"
			s.Path = s.Coordinate.manifestPath(false)
		},
		"coordinate version": func(s *Snapshot) { s.Coordinate.Version = "1.21.0"; s.Path = s.Coordinate.manifestPath(false) },
		"empty":              func(s *Snapshot) { s.Content = nil },
		"oversized":          func(s *Snapshot) { s.Content = make([]byte, MaxManifestBytes+1) },
	} {
		t.Run(name, func(t *testing.T) {
			s := fixtureSnapshot(fixtureManifest)
			change(&s)
			if _, err := s.Inspect(); !errors.Is(err, ErrManifest) {
				t.Fatal("changed binding accepted")
			}
		})
	}
}

func TestSnapshotRejectsAmbiguousOrUnboundedYAML(t *testing.T) {
	for name, content := range map[string]string{
		"duplicate root":              fixtureManifest + "Scope: user\n",
		"duplicate nested":            strings.Replace(fixtureManifest, "- Architecture: x64", "- Architecture: x64\n  Architecture: arm64", 1),
		"alias":                       strings.Replace(fixtureManifest, "Scope: machine", "Scope: &scope machine\nAlias: *scope", 1),
		"unused anchor":               strings.Replace(fixtureManifest, "Scope: machine", "Scope: &scope machine", 1),
		"merge":                       strings.Replace(fixtureManifest, "Scope: machine", "<<: {Scope: machine}", 1),
		"custom tag":                  strings.Replace(fixtureManifest, "Scope: machine", "Scope: !command machine", 1),
		"binary tag":                  strings.Replace(fixtureManifest, "Scope: machine", "Scope: !!binary bWFjaGluZQ==", 1),
		"multiple documents":          fixtureManifest + "---\nScope: user\n",
		"empty extra document":        fixtureManifest + "---\n",
		"sequence document":           "- " + strings.ReplaceAll(fixtureManifest, "\n", "\n  "),
		"complex key":                 fixtureManifest + "? [complex, key]\n: value\n",
		"schema":                      strings.Replace(fixtureManifest, "1.12.0", "9.0.0", 1),
		"unknown intermediate schema": strings.Replace(fixtureManifest, "1.12.0", "1.11.0", 1),
		"missing installers":          strings.Replace(fixtureManifest, "Installers:", "Other:", 1),
		"empty installers":            strings.Replace(fixtureManifest, "Installers:", "Installers: []\nOther:", 1),
		"unknown architecture":        strings.Replace(fixtureManifest, "Architecture: x64", "Architecture: any", 1),
		"missing architecture":        strings.Replace(fixtureManifest, "Architecture: x64", "Other: x64", 1),
		"too deep":                    fixtureManifest + "Nested: " + strings.Repeat("[", 20) + "value" + strings.Repeat("]", 20) + "\n",
		"too many nodes":              fixtureManifest + "Nodes: [" + strings.Repeat("a,", maxManifestNodes) + "]\n",
		"too many installers":         strings.Replace(fixtureManifest, "Installers:\n", "Installers:\n"+strings.Repeat("- Architecture: x64\n", 256), 1),
	} {
		t.Run(name, func(t *testing.T) {
			s := fixtureSnapshot(content)
			if _, err := s.Inspect(); !errors.Is(err, ErrManifest) {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
	singleton := fixtureSnapshot(strings.Replace(fixtureManifest, "ManifestType: installer", "ManifestType: singleton", 1))
	singleton.Path = singleton.Coordinate.manifestPath(true)
	if _, err := singleton.Inspect(); err != nil {
		t.Fatal(err)
	}
}

func TestExactCoordinate(t *testing.T) {
	for _, c := range []Coordinate{fixtureCoordinate, {"Publisher.Package.Component", "2026.09 beta"}, {"Päckage.Editor", "1.0"}, {"Example.Editor", "1.0%20#hash"}} {
		if !c.Valid() {
			t.Fatalf("valid coordinate rejected: %#v", c)
		}
	}
	for _, c := range []Coordinate{{"Example", "1.0"}, {"Example..Editor", "1.0"}, {".Example.Editor", "1.0"}, {"Example.Editor.", "1.0"}, {"Example.Editor", ".."}, {"Example.Editor", "../other"}, {"Example.Editor", "1.0?query"}, {"Example.Editor", "1\\2"}, {" Example.Editor", "1.0"}, {"Example.Editor", "1.0\n"}, {"Example. Editor", "1.0"}, {"Example.Editor", strings.Repeat("a", 129)}, {"Example." + strings.Repeat("a", 33), "1.0"}, {"Example.Editor", "-1.0"}} {
		if c.Valid() {
			t.Fatalf("invalid coordinate accepted: %#v", c)
		}
	}
}

func ownedSource(t *testing.T, handler http.HandlerFunc) *Source {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	source := NewSource()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	source.client.Transport = transport
	t.Cleanup(source.Close)
	return source
}

func sourceRef() string {
	return `{"ref":"refs/heads/master","object":{"type":"commit","sha":"` + fixtureCommit + `"}}`
}

func TestSourcePinsOneCommitAndUsesOnlyFixedHTTPSHosts(t *testing.T) {
	var mu sync.Mutex
	var requests []string
	source := ownedSource(t, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.URL.RawQuery != "" {
			t.Error("unexpected source request")
		}
		mu.Lock()
		requests = append(requests, r.Host+r.URL.Path)
		mu.Unlock()
		switch r.Host + r.URL.Path {
		case "api.github.com/repos/" + Repository + "/git/ref/heads/master":
			if r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" || r.Header.Get("Accept") != "application/vnd.github+json" {
				t.Error("source API contract not pinned")
			}
			io.WriteString(w, sourceRef())
		case "raw.githubusercontent.com/" + Repository + "/" + fixtureCommit + "/" + fixtureCoordinate.manifestPath(false):
			io.WriteString(w, fixtureManifest)
		default:
			t.Error("request escaped pinned source")
			http.NotFound(w, r)
		}
	})
	snapshot, err := source.Fetch(t.Context(), fixtureCoordinate)
	if err != nil || snapshot.Commit != fixtureCommit {
		t.Fatalf("source fetch: %v", err)
	}
	if _, err = snapshot.Inspect(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("unexpected request count: %d", len(requests))
	}
}

func TestSourceFallbackOnlyForAbsentInstallerFile(t *testing.T) {
	for _, status := range []int{404, 403, 429, 500, 301, 302, 307, 308, 200} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			source := ownedSource(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if strings.HasSuffix(r.URL.Path, ".installer.yaml") {
					w.Header().Set("Location", "https://example.invalid/private?credential=fixture")
					w.WriteHeader(status)
					io.WriteString(w, "invalid manifest, never eligible for fallback")
				} else {
					io.WriteString(w, strings.Replace(fixtureManifest, "ManifestType: installer", "ManifestType: singleton", 1))
				}
			})
			snapshot, err := source.FetchAt(t.Context(), fixtureCoordinate, fixtureCommit)
			if status == 404 {
				if err != nil || snapshot.Path != fixtureCoordinate.manifestPath(true) || calls.Load() != 2 {
					t.Fatalf("singleton fallback: %v", err)
				}
			} else {
				if err == nil || snapshot != nil || calls.Load() != 1 {
					t.Fatal("failed or redirected source triggered another request")
				}
				if strings.Contains(err.Error(), "credential") || strings.Contains(err.Error(), "example.invalid") {
					t.Fatal("source error exposed location")
				}
			}
		})
	}
}

func TestSourceRejectsMalformedRefAndBoundsResponse(t *testing.T) {
	for name, body := range map[string]string{
		"malformed": "{", "wrong ref": strings.Replace(sourceRef(), "refs/heads/master", "refs/heads/other", 1),
		"not a commit": strings.Replace(sourceRef(), "\"commit\"", "\"tag\"", 1), "short hash": strings.Replace(sourceRef(), fixtureCommit, "abc", 1),
		"trailing JSON": sourceRef() + "{}", "too large": strings.Repeat("a", (32<<10)+1), "empty": "",
		"duplicate ref":         strings.Replace(sourceRef(), `"ref":`, `"ref":"refs/heads/other","ref":`, 1),
		"wrong field case":      strings.Replace(sourceRef(), `"sha":`, `"SHA":`, 1),
		"duplicate escaped SHA": strings.Replace(sourceRef(), `"sha":`, `"\u0073ha":"ffffffffffffffffffffffffffffffffffffffff","sha":`, 1),
		"deep JSON":             strings.Replace(sourceRef(), `"ref":`, `"extra":`+strings.Repeat("[", 10)+"0"+strings.Repeat("]", 10)+`,"ref":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			source := ownedSource(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, body) })
			if snapshot, err := source.Fetch(t.Context(), fixtureCoordinate); !errors.Is(err, ErrSource) || snapshot != nil || calls.Load() != 1 {
				t.Fatal("malformed ref admitted source fetch")
			}
		})
	}
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprint("manifest overflow ", chunked), func(t *testing.T) {
			var calls atomic.Int32
			source := ownedSource(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if chunked {
					w.(http.Flusher).Flush()
				}
				io.WriteString(w, strings.Repeat("a", MaxManifestBytes+1))
			})
			if snapshot, err := source.FetchAt(t.Context(), fixtureCoordinate, fixtureCommit); !errors.Is(err, ErrSource) || snapshot != nil || calls.Load() != 1 {
				t.Fatal("oversized source accepted or retried")
			}
		})
	}
	var calls atomic.Int32
	source := ownedSource(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); http.NotFound(w, r) })
	if _, err := source.FetchAt(t.Context(), fixtureCoordinate, fixtureCommit); !errors.Is(err, ErrNotFound) || calls.Load() != 2 {
		t.Fatal("absent package was not bounded to two filenames")
	}
	if _, err := source.Fetch(t.Context(), Coordinate{"../outside", "1.0"}); !errors.Is(err, ErrCoordinate) || calls.Load() != 2 {
		t.Fatal("invalid coordinate reached source")
	}
	if _, err := source.FetchAt(t.Context(), fixtureCoordinate, "master"); !errors.Is(err, ErrCoordinate) || calls.Load() != 2 {
		t.Fatal("mutable ref reached source")
	}
}

func TestSourceEscapesCoordinateWithoutQueryOrHostChanges(t *testing.T) {
	coordinate := Coordinate{Identifier: "Example.Editor", Version: "1.0%20#hash"}
	content := strings.Replace(fixtureManifest, "PackageVersion: 1.20.0", "PackageVersion: '1.0%20#hash'", 1)
	source := ownedSource(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "raw.githubusercontent.com" || r.URL.Path != "/"+Repository+"/"+fixtureCommit+"/"+coordinate.manifestPath(false) || r.URL.RawQuery != "" || !strings.Contains(r.URL.EscapedPath(), "1.0%2520%23hash") {
			t.Error("coordinate changed source or path semantics")
		}
		io.WriteString(w, content)
	})
	if _, err := source.FetchAt(t.Context(), coordinate, fixtureCommit); err != nil {
		t.Fatal(err)
	}
}

func TestSourceCancellationJoinsTheOwnedRequest(t *testing.T) {
	started, joined := make(chan struct{}), make(chan struct{})
	source := ownedSource(t, func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(joined) })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := source.FetchAt(ctx, fixtureCoordinate, fixtureCommit); result <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request never started")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, ErrSource) {
			t.Fatal("cancelled source succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("source ignored cancellation")
	}
	select {
	case <-joined:
	case <-time.After(3 * time.Second):
		t.Fatal("source request retained the connection after cancellation")
	}
}

func FuzzSnapshot(f *testing.F) {
	f.Add(fixtureManifest)
	f.Add("{}")
	f.Add(fixtureManifest + "---\n")
	f.Fuzz(func(t *testing.T, content string) {
		if len(content) > MaxManifestBytes {
			t.Skip()
		}
		snapshot := fixtureSnapshot(content)
		manifest, err := snapshot.Inspect()
		if err == nil {
			if manifest.Root == nil || len(manifest.Installers) == 0 {
				t.Fatal("accepted empty manifest")
			}
			if _, err := snapshot.Inspect(); err != nil {
				t.Fatal("snapshot inspection changed its evidence")
			}
		}
	})
}
