//go:build linux || darwin

package acmeissuer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/gateway"
)

func readinessIdentity(config Config) string {
	data, _ := json.Marshal(config)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// Ready validates retained material while the owning service holds both leases.
// A network attempt may be running or temporarily failing; the existing public
// certificate must still be valid. No provider call, write or repair occurs.
func (s *Service) Ready() error {
	s.lifetime.RLock()
	defer s.lifetime.RUnlock()
	if s.closed || s.config.CheckInputs(s.binary) != nil || s.state.unchanged() != nil || s.publication.unchanged() != nil {
		return ErrNotReady
	}
	var paired installationBinding
	for index, directory := range []*directory{s.state, s.publication} {
		data, err := readProtected(filepath.Join(directory.path, "installation.json"), 8192, true)
		var actual installationBinding
		if err != nil || decodeJSON(data, &actual) != nil || actual.Version != 1 || actual.Origin != s.config.PublicOrigin || actual.Directory != s.config.DirectoryURL || actual.Email != s.config.Email || actual.Provider != s.config.Provider {
			return ErrNotReady
		}
		id, err := uuid.Parse(actual.Installation)
		if err != nil || id == uuid.Nil || id.String() != actual.Installation || actual.Installation != s.installationID || index != 0 && actual != paired {
			return ErrNotReady
		}
		paired = actual
	}
	if s.state.account(s.config, true, true, false) != nil {
		return ErrNotReady
	}
	current, err := s.publication.current(s.config.PublicOrigin)
	if err != nil || current == nil {
		return ErrNotReady
	}
	_, err = gateway.NewPublicTLS(s.config.PublicOrigin,
		filepath.Join(s.publication.path, current.Name, "fullchain.pem"), filepath.Join(s.publication.path, current.Name, "private.pem"))
	if err != nil || s.state.unchanged() != nil || s.publication.unchanged() != nil {
		return ErrNotReady
	}
	return nil
}

type ReadinessServer struct {
	server   *http.Server
	listener *net.UnixListener
	parent   *os.Root
	path     string
	parentID os.FileInfo
	socketID os.FileInfo
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	closing  bool
	requests sync.WaitGroup
}

type readinessListener struct {
	net.Listener
	slots chan struct{}
}

type readinessConnection struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
}

func (l *readinessListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &readinessConnection{Conn: connection, slots: l.slots}, nil
		default:
			_ = connection.Close()
		}
	}
}

func (c *readinessConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.slots })
	return err
}

func readinessParent(path string) (*os.Root, os.FileInfo, error) {
	// Stay within the shortest supported Unix-domain socket pathname limit.
	if !cleanAbsolute(path) || len(path) > 100 {
		return nil, nil, ErrNotReady
	}
	parent := filepath.Dir(path)
	canonical, err := filepath.EvalSymlinks(parent)
	info, statErr := os.Lstat(parent)
	if err != nil || canonical != parent || statErr != nil || !info.IsDir() || !protected(info, true) {
		return nil, nil, ErrNotReady
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, nil, ErrNotReady
	}
	held, err := root.Stat(".")
	if err != nil || !os.SameFile(info, held) {
		_ = root.Close()
		return nil, nil, ErrNotReady
	}
	return root, info, nil
}

// ListenReadiness binds only a private local socket. Start it after Open and
// close it before the service; no TCP listener or public status file is created.
func (s *Service) ListenReadiness(path string) (*ReadinessServer, error) {
	s.lifetime.RLock()
	defer s.lifetime.RUnlock()
	if s.closed || s.state.unchanged() != nil || s.publication.unchanged() != nil {
		return nil, ErrNotReady
	}
	parent, parentID, err := readinessParent(path)
	if err != nil {
		return nil, err
	}
	ready := false
	defer func() {
		if !ready {
			_ = parent.Close()
		}
	}()
	name := filepath.Base(path)
	if existing, err := parent.Lstat(name); err == nil {
		if existing.Mode()&os.ModeSocket == 0 || !protected(existing, true) {
			return nil, ErrNotReady
		}
		connection, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return nil, ErrNotReady
		}
		actual, statErr := parent.Lstat(name)
		if !errors.Is(err, syscall.ECONNREFUSED) || statErr != nil || !os.SameFile(existing, actual) || s.state.unchanged() != nil || s.publication.unchanged() != nil || parent.Remove(name) != nil {
			return nil, ErrNotReady
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotReady
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, ErrNotReady
	}
	listener.SetUnlinkOnClose(false)
	server := &ReadinessServer{listener: listener, parent: parent, parentID: parentID, path: path, done: make(chan struct{})}
	server.socketID, err = parent.Lstat(name)
	if err != nil || server.socketID.Mode()&os.ModeSocket == 0 || parent.Chmod(name, 0600) != nil || !server.unchanged() {
		_ = listener.Close()
		server.removeSocket()
		return nil, ErrNotReady
	}
	identity := readinessIdentity(s.config)
	bounded := make(chan struct{}, 8)
	server.server = &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second,
		IdleTimeout: time.Second, MaxHeaderBytes: 1024, ErrorLog: log.New(io.Discard, "", 0), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			server.mu.Lock()
			if server.closing {
				server.mu.Unlock()
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			server.requests.Add(1)
			server.mu.Unlock()
			defer server.requests.Done()
			select {
			case bounded <- struct{}{}:
				defer func() { <-bounded }()
			default:
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if r.Method != http.MethodGet || r.URL.RequestURI() != "/ready" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Header.Values("X-OpenUEM-Configuration")) != 1 || r.Header.Get("X-OpenUEM-Configuration") != identity || !server.unchanged() || s.Ready() != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})}
	server.server.SetKeepAlivesEnabled(false)
	go func() {
		defer close(server.done)
		_ = server.server.Serve(&readinessListener{Listener: listener, slots: make(chan struct{}, 16)})
	}()
	ready = true
	return server, nil
}

func (s *ReadinessServer) unchanged() bool {
	parent, err := os.Lstat(filepath.Dir(s.path))
	if err != nil || !os.SameFile(parent, s.parentID) || !protected(parent, true) {
		return false
	}
	actual, err := s.parent.Lstat(filepath.Base(s.path))
	return err == nil && s.socketID != nil && actual.Mode()&os.ModeSocket != 0 && protected(actual, true) && os.SameFile(actual, s.socketID)
}

func (s *ReadinessServer) removeSocket() {
	if s.unchanged() {
		_ = s.parent.Remove(filepath.Base(s.path))
	}
}

func (s *ReadinessServer) Close() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closing = true
		s.mu.Unlock()
		_ = s.server.Close()
		<-s.done
		s.requests.Wait()
		s.removeSocket()
		_ = s.parent.Close()
	})
}

// CheckReadiness asks the retained service, without opening its state, acquiring
// leases, contacting the provider or creating any file. The parent and socket
// must belong to the trusted account; no OS trust or transport bypass is added.
func CheckReadiness(ctx context.Context, config Config, path string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if config.Validate() != nil {
		return ErrNotReady
	}
	parent, parentID, err := readinessParent(path)
	if err != nil {
		return err
	}
	defer parent.Close()
	info, err := parent.Lstat(filepath.Base(path))
	if err != nil || info.Mode()&os.ModeSocket == 0 || !protected(info, true) {
		return ErrNotReady
	}
	identity := &ReadinessServer{parent: parent, parentID: parentID, socketID: info, path: path}
	dialer := net.Dialer{Timeout: time.Second}
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://local/ready", nil)
	request.Header.Set("X-OpenUEM-Configuration", readinessIdentity(config))
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrNotReady
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent || !identity.unchanged() {
		return ErrNotReady
	}
	return nil
}
