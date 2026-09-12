package secrets

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/open-uem/nats/enrollment/keyfile"
)

// provisioningDirectory holds the initial inventory and directory identity.
// Callers keep ancestors trusted and publish readiness only after validating all
// expected files. Writes never replace existing entries, including partial ones.
type provisioningDirectory struct {
	ctx        context.Context
	path       string
	identity   os.FileInfo
	present    map[string]bool
	afterWrite func(string) error
	readOnly   bool
}

func openProvisioning(ctx context.Context, path string, names []string, afterWrite func(string) error) (*provisioningDirectory, error) {
	return provisioning(ctx, path, names, afterWrite, true)
}

func readProvisioning(ctx context.Context, path string, names []string) (*provisioningDirectory, error) {
	return provisioning(ctx, path, names, nil, false)
}

func provisioning(ctx context.Context, path string, names []string, afterWrite func(string) error, create bool) (*provisioningDirectory, error) {
	if !supported() || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == filepath.Dir(path) {
		return nil, ErrConfiguration
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if create {
		if keyfile.CreateDirectory(path) != nil || syncDirectory(filepath.Dir(path)) != nil {
			return nil, ErrState
		}
	} else if keyfile.CheckDirectory(path) != nil {
		return nil, ErrState
	}
	identity, err := os.Lstat(path)
	if err != nil {
		return nil, ErrState
	}
	d := &provisioningDirectory{ctx: ctx, path: path, identity: identity, present: map[string]bool{}, afterWrite: afterWrite, readOnly: !create}
	if err := d.check(); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrState
	}
	entries, err := file.ReadDir(len(names) + 1)
	file.Close()
	if err != nil && err != io.EOF || len(entries) > len(names) {
		return nil, ErrState
	}
	for _, entry := range entries {
		if !slices.Contains(names, entry.Name()) {
			return nil, ErrState
		}
		d.present[entry.Name()] = true
	}
	return d, nil
}

func (d *provisioningDirectory) check() error {
	current, err := os.Lstat(d.path)
	if err != nil || !os.SameFile(d.identity, current) || keyfile.CheckDirectory(d.path) != nil {
		return ErrState
	}
	return d.ctx.Err()
}

func (d *provisioningDirectory) read(name string, limit int64) ([]byte, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	return read(filepath.Join(d.path, name), limit)
}

func (d *provisioningDirectory) write(name string, value []byte) error {
	if d.readOnly {
		return ErrState
	}
	if err := d.check(); err != nil {
		return err
	}
	if keyfile.Create(filepath.Join(d.path, name), value) != nil || syncDirectory(d.path) != nil {
		return ErrState
	}
	if d.afterWrite != nil {
		return d.afterWrite(name)
	}
	return nil
}
