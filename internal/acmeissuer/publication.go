//go:build linux || darwin

package acmeissuer

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/gateway"
)

type Generation struct {
	Version           int       `json:"version"`
	Origin            string    `json:"origin"`
	Name              string    `json:"name"`
	CertificateSHA256 string    `json:"certificate_sha256"`
	CreatedAt         time.Time `json:"created_at"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
}

func generationName(name string) bool {
	if !strings.HasPrefix(name, "generation-") {
		return false
	}
	id, err := uuid.Parse(strings.TrimPrefix(name, "generation-"))
	return err == nil && name == "generation-"+id.String()
}

func (d *directory) current(origin string) (*Generation, error) {
	if d.unchanged() != nil {
		return nil, ErrState
	}
	name, err := d.root.Readlink("current")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !generationName(name) {
		return nil, ErrState
	}
	return d.readGeneration(origin, name)
}

func (d *directory) readGeneration(origin, name string) (*Generation, error) {
	if !generationName(name) {
		return nil, ErrState
	}
	info, err := d.root.Lstat(name)
	if err != nil || !info.IsDir() || !protected(info, true) {
		return nil, ErrState
	}
	data, err := readProtected(filepath.Join(d.path, name, "generation.json"), 8192, true)
	if err != nil {
		return nil, ErrState
	}
	var result Generation
	if decodeJSON(data, &result) != nil || result.Version != 1 || result.Origin != origin || result.Name != name || result.CreatedAt.IsZero() || !result.NotAfter.After(result.NotBefore) {
		return nil, ErrState
	}
	certificate, err := readProtected(filepath.Join(d.path, name, "fullchain.pem"), 1<<20, true)
	if err != nil {
		return nil, ErrState
	}
	digest := sha256.Sum256(certificate)
	if result.CertificateSHA256 != hex.EncodeToString(digest[:]) {
		return nil, ErrState
	}
	key, err := readProtected(filepath.Join(d.path, name, "private.pem"), 64<<10, true)
	if err != nil {
		return nil, ErrState
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		return nil, ErrState
	}
	notBefore, notAfter, err := certificateBounds(pair.Certificate)
	if err != nil || !notBefore.Equal(result.NotBefore) || !notAfter.Equal(result.NotAfter) {
		return nil, ErrState
	}
	return &result, nil
}

func certificateBounds(chain [][]byte) (time.Time, time.Time, error) {
	var notBefore, notAfter time.Time
	for i, raw := range chain {
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			return time.Time{}, time.Time{}, ErrPublication
		}
		if i == 0 || certificate.NotBefore.After(notBefore) {
			notBefore = certificate.NotBefore
		}
		if i == 0 || certificate.NotAfter.Before(notAfter) {
			notAfter = certificate.NotAfter
		}
	}
	return notBefore, notAfter, nil
}

// publish creates durable immutable files before atomically switching one relative
// symlink. The gateway never mounts the ACME account or provider credential state.
func (d *directory) publish(c Config) (*Generation, bool, error) {
	if d.unchanged() != nil {
		return nil, false, ErrState
	}
	certificate, err := readProtected(filepath.Join(c.StateDirectory, "lego", "certificates", "gateway.crt"), 1<<20, true)
	if err != nil {
		return nil, false, ErrPublication
	}
	key, err := readProtected(filepath.Join(c.StateDirectory, "lego", "certificates", "gateway.key"), 64<<10, true)
	if err != nil {
		return nil, false, ErrPublication
	}
	defer clear(key)
	name := "generation-" + uuid.NewString()
	if d.root.Mkdir(name, 0700) != nil {
		return nil, false, ErrPublication
	}
	selected := false
	defer func() {
		// Remove only this invocation's unpublished staging directory. Interrupted
		// or unrecognized directories from earlier runs remain operator-owned.
		if !selected && d.unchanged() == nil {
			_ = d.root.RemoveAll(name)
		}
	}()
	stage, err := d.root.OpenRoot(name)
	if err != nil {
		return nil, false, ErrPublication
	}
	defer stage.Close()
	if writeExclusive(stage, "fullchain.pem", certificate) != nil || writeExclusive(stage, "private.pem", key) != nil {
		return nil, false, ErrPublication
	}
	publicTLS, err := gateway.NewPublicTLS(c.PublicOrigin, filepath.Join(d.path, name, "fullchain.pem"), filepath.Join(d.path, name, "private.pem"))
	if err != nil {
		return nil, false, ErrPublication
	}
	// Read the already validated chain for public scheduling metadata only.
	var chain [][]byte
	for rest := certificate; len(rest) > 0; {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		chain = append(chain, block.Bytes)
		rest = remaining
	}
	notBefore, notAfter, err := certificateBounds(chain)
	if err != nil {
		return nil, false, ErrPublication
	}
	if _, err := publicTLS.Config().GetConfigForClient(nil); err != nil {
		return nil, false, ErrPublication
	}
	digest := sha256.Sum256(certificate)
	result := Generation{Version: 1, Origin: c.PublicOrigin, Name: name, CertificateSHA256: hex.EncodeToString(digest[:]), CreatedAt: time.Now().UTC(), NotBefore: notBefore, NotAfter: notAfter}
	current, err := d.current(c.PublicOrigin)
	if err != nil {
		return nil, false, err
	}
	if current != nil && current.CertificateSHA256 == result.CertificateSHA256 {
		return current, false, nil
	}
	metadata, err := json.Marshal(result)
	if err != nil || writeExclusive(stage, "generation.json", metadata) != nil || syncRoot(stage) != nil || syncRoot(d.root) != nil {
		return nil, false, ErrPublication
	}
	if d.unchanged() != nil {
		return nil, false, ErrState
	}
	link := ".current-" + uuid.NewString()
	if d.root.Symlink(name, link) != nil {
		return nil, false, ErrPublication
	}
	if d.root.Rename(link, "current") != nil {
		_ = d.root.Remove(link)
		return nil, false, ErrPublication
	}
	selected = true
	if syncRoot(d.root) != nil {
		return nil, false, ErrPublication
	}
	return &result, true, nil
}

// Keep five complete generations. Never traverse a link or remove an incomplete,
// unrecognized or foreign directory during automatic retention.
func (d *directory) prune(origin, current string) error {
	if d.unchanged() != nil {
		return ErrState
	}
	file, err := d.root.Open(".")
	if err != nil {
		return ErrState
	}
	entries, readErr := file.ReadDir(513)
	_ = file.Close()
	if (readErr != nil && readErr != io.EOF) || len(entries) > 512 {
		return ErrState
	}
	var generations []*Generation
	for _, entry := range entries {
		if !entry.IsDir() || !generationName(entry.Name()) {
			continue
		}
		generation, err := d.readGeneration(origin, entry.Name())
		if err != nil {
			continue
		}
		generationDir, err := d.root.Open(entry.Name())
		if err != nil {
			continue
		}
		children, readErr := generationDir.ReadDir(4)
		_ = generationDir.Close()
		if (readErr != nil && readErr != io.EOF) || len(children) != 3 {
			continue
		}
		valid := true
		for _, child := range children {
			if !child.Type().IsRegular() || (child.Name() != "fullchain.pem" && child.Name() != "private.pem" && child.Name() != "generation.json") {
				valid = false
			}
		}
		if valid {
			generations = append(generations, generation)
		}
	}
	sort.Slice(generations, func(i, j int) bool {
		if generations[i].CreatedAt.Equal(generations[j].CreatedAt) {
			return generations[i].Name < generations[j].Name
		}
		return generations[i].CreatedAt.After(generations[j].CreatedAt)
	})
	for i, generation := range generations {
		if i < 5 || generation.Name == current {
			continue
		}
		if d.unchanged() != nil {
			return ErrState
		}
		actual, err := d.root.Readlink("current")
		if err != nil || actual != current {
			return ErrState
		}
		if err := d.root.RemoveAll(generation.Name); err != nil {
			return ErrState
		}
	}
	return syncRoot(d.root)
}
