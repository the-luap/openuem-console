//go:build linux || darwin

package acmeissuer

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/google/uuid"
)

type directory struct {
	path  string
	root  *os.Root
	info  os.FileInfo
	lease *os.File
}

func protected(info os.FileInfo, secret bool) bool {
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (metadata.Uid != 0 && metadata.Uid != uint32(os.Geteuid())) {
		return false
	}
	mask := os.FileMode(0022)
	if secret {
		mask = 0077
	}
	return info.Mode().Perm()&mask == 0 && (info.IsDir() || metadata.Nlink == 1)
}

func readProtected(path string, limit int64, secret bool) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrState
	}
	defer file.Close()
	return readProtectedFile(file, limit, secret)
}

func readProtectedFile(file *os.File, limit int64, secret bool) ([]byte, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !protected(info, secret) || info.Size() < 1 || info.Size() > limit {
		return nil, ErrState
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, ErrState
	}
	return data, nil
}

func openDirectory(path string) (*directory, error) {
	if !cleanAbsolute(path) {
		return nil, ErrState
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, ErrState
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || !protected(info, true) {
		return nil, ErrState
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, ErrState
	}
	d := &directory{path: path, root: root, info: info}
	ready := false
	defer func() {
		if !ready {
			d.close()
		}
	}()
	d.lease, err = root.OpenFile("issuer.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, ErrState
	}
	leaseInfo, err := d.lease.Stat()
	if err != nil || !leaseInfo.Mode().IsRegular() || !protected(leaseInfo, true) {
		return nil, ErrState
	}
	if err = syscall.Flock(int(d.lease.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, ErrState
	}
	if d.unchanged() != nil {
		return nil, ErrState
	}
	ready = true
	return d, nil
}

func (d *directory) unchanged() error {
	actual, err := os.Lstat(d.path)
	if err != nil || !actual.IsDir() || !os.SameFile(d.info, actual) || !protected(actual, true) {
		return ErrState
	}
	held, err := d.root.Stat(".")
	if err != nil || !os.SameFile(d.info, held) {
		return ErrState
	}
	leaseInfo, err := d.lease.Stat()
	if err != nil || !protected(leaseInfo, true) {
		return ErrState
	}
	leasePath, err := d.root.Lstat("issuer.lock")
	if err != nil || !leasePath.Mode().IsRegular() || !os.SameFile(leasePath, leaseInfo) {
		return ErrState
	}
	return nil
}

func (d *directory) close() {
	if d.lease != nil {
		_ = d.lease.Close()
	}
	if d.root != nil {
		_ = d.root.Close()
	}
}

func syncRoot(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func writeExclusive(root *os.Root, name string, data []byte) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

type installationBinding struct {
	Version      int    `json:"version"`
	Installation string `json:"installation"`
	Origin       string `json:"origin"`
	Directory    string `json:"directory"`
	Email        string `json:"email"`
	Provider     string `json:"provider"`
}

// A restored publication cannot silently create a replacement account after
// losing its matching state volume. Both bindings must be new or retained.
func bindInstallation(state, publication *directory, c Config) (string, error) {
	_, stateErr := state.root.Lstat("installation.json")
	_, publicErr := publication.root.Lstat("installation.json")
	stateMissing, publicMissing := errors.Is(stateErr, os.ErrNotExist), errors.Is(publicErr, os.ErrNotExist)
	if stateMissing != publicMissing || (stateErr != nil && !stateMissing) || (publicErr != nil && !publicMissing) {
		return "", ErrState
	}
	id := uuid.NewString()
	if !stateMissing {
		data, err := readProtected(filepath.Join(state.path, "installation.json"), 8192, true)
		var retained installationBinding
		if err != nil || decodeJSON(data, &retained) != nil {
			return "", ErrState
		}
		parsed, err := uuid.Parse(retained.Installation)
		if err != nil || parsed == uuid.Nil || parsed.String() != retained.Installation {
			return "", ErrState
		}
		id = retained.Installation
	}
	if state.bind(c, id) != nil || publication.bind(c, id) != nil {
		return "", ErrState
	}
	return id, nil
}

// Binding prevents accidental staging/production, origin, account or provider
// substitution in retained state. It is an immutable operator configuration,
// not an authority supplied by a DNS response or an issued certificate.
func (d *directory) bind(c Config, id string) error {
	binding := installationBinding{1, id, c.PublicOrigin, c.DirectoryURL, c.Email, c.Provider}
	data, err := json.Marshal(binding)
	if err != nil {
		return ErrState
	}
	path := filepath.Join(d.path, "installation.json")
	if _, err = d.root.Lstat("installation.json"); errors.Is(err, os.ErrNotExist) {
		file, err := d.root.Open(".")
		if err != nil {
			return ErrState
		}
		entries, readErr := file.ReadDir(3)
		_ = file.Close()
		if readErr != nil && readErr != io.EOF {
			return ErrState
		}
		if len(entries) != 1 || entries[0].Name() != "issuer.lock" {
			return ErrState
		}
		if err := writeExclusive(d.root, "installation.json", data); err != nil {
			return ErrState
		}
		if syncRoot(d.root) != nil {
			return ErrState
		}
	} else if err != nil {
		return ErrState
	}
	actual, err := readProtected(path, 8192, true)
	if err != nil || !bytes.Equal(actual, data) || d.unchanged() != nil {
		return ErrState
	}
	return nil
}

func (d *directory) writeJSON(name string, value any) error {
	if d.unchanged() != nil {
		return ErrState
	}
	data, err := json.Marshal(value)
	if err != nil {
		return ErrState
	}
	temporary := ".pending-" + uuid.NewString()
	if err := writeExclusive(d.root, temporary, data); err != nil {
		return ErrState
	}
	if err := d.root.Rename(temporary, name); err != nil {
		return ErrState
	}
	if syncRoot(d.root) != nil {
		return ErrState
	}
	return nil
}
