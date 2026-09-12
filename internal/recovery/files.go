package recovery

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"filippo.io/age"
	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment/keyfile"
)

var environmentName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
var windowsDeviceName = regexp.MustCompile(`^(com|lpt)[0-9]$`)
var fileName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

func decodeJSON(data []byte, target any) error {
	// encoding/json accepts duplicate object keys. Recovery envelopes and file
	// specifications must have one interpretation before any data is restored.
	check := json.NewDecoder(bytes.NewReader(data))
	check.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 16 {
			return ErrArchive
		}
		token, err := check.Token()
		if err != nil {
			return ErrArchive
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		count := 0
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for check.More() {
				key, err := check.Token()
				if err != nil {
					return ErrArchive
				}
				name, ok := key.(string)
				if !ok || seen[strings.ToLower(name)] || count >= 256 {
					return ErrArchive
				}
				seen[strings.ToLower(name)] = true
				count++
				if visit(depth+1) != nil {
					return ErrArchive
				}
			}
		case '[':
			for check.More() {
				if count >= 256 || visit(depth+1) != nil {
					return ErrArchive
				}
				count++
			}
		default:
			return ErrArchive
		}
		if _, err := check.Token(); err != nil {
			return ErrArchive
		}
		return nil
	}
	if visit(0) != nil {
		return ErrArchive
	}
	if _, err := check.Token(); err != io.EOF {
		return ErrArchive
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return ErrArchive
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return ErrArchive
	}
	return nil
}

func LoadSpecification(path string) (Specification, error) {
	var spec Specification
	data, err := readPrivate(path, 1<<20)
	if err != nil {
		return spec, ErrConfig
	}
	defer clear(data)
	if decodeJSON(data, &spec) != nil {
		return spec, ErrConfig
	}
	return spec, nil
}

func readPrivate(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrFile
	}
	f, err := keyfile.Open(path, limit)
	if err != nil {
		return nil, ErrFile
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, ErrFile
	}
	return data, nil
}

func collect(spec Specification, id string) (*recoveryBundle, error) {
	if len(spec.Environment) > 128 || len(spec.Files) > 128 {
		return nil, ErrConfig
	}
	b := &recoveryBundle{Version: formatVersion, ID: id, Environment: map[string]string{}, Files: map[string][]byte{}}
	ready := false
	defer func() {
		if !ready {
			b.clear()
		}
	}()
	total := 0
	for _, name := range spec.Environment {
		if !environmentName.MatchString(name) {
			return nil, ErrConfig
		}
		if _, exists := b.Environment[name]; exists {
			return nil, ErrConfig
		}
		value, ok := os.LookupEnv(name)
		if !ok || len(value) == 0 || len(value) > 1<<20 || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return nil, ErrConfig
		}
		b.Environment[name] = value
		total += len(value)
		if total > maxRecoveryBytes/2 {
			return nil, ErrConfig
		}
	}
	for _, source := range spec.Files {
		if !validFileName(source.Name) {
			return nil, ErrConfig
		}
		if _, exists := b.Files[strings.ToLower(source.Name)]; exists {
			return nil, ErrConfig
		}
		// Logical names are case-insensitive to remain unambiguous on Windows.
		data, err := readPrivate(source.Path, maxFileBytes)
		if err != nil {
			return nil, err
		}
		total += len(data)
		if total > maxRecoveryBytes/2 {
			clear(data)
			return nil, ErrConfig
		}
		b.Files[strings.ToLower(source.Name)] = data
	}
	ready = true
	return b, nil
}

func validFileName(name string) bool {
	name = strings.ToLower(name)
	if !fileName.MatchString(name) || strings.HasSuffix(name, ".") || name == "environment.json" || name == "recovery.json" || name == "completed.json" {
		return false
	}
	base := strings.SplitN(name, ".", 2)[0]
	if base == "con" || base == "prn" || base == "aux" || base == "nul" || windowsDeviceName.MatchString(base) {
		return false
	}
	return true
}

func identities(path string) ([]age.Identity, error) {
	data, err := readPrivate(path, 64<<10)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	keys, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil || len(keys) != 1 {
		return nil, ErrConfig
	}
	return keys, nil
}

func recipient(value string) (age.Recipient, error) {
	if len(value) > 64<<10 {
		return nil, ErrConfig
	}
	keys, err := age.ParseRecipients(strings.NewReader(value))
	if err != nil || len(keys) != 1 {
		return nil, ErrConfig
	}
	return keys[0], nil
}

// GenerateIdentity prints only a recipient. Its private identity is written to a
// new protected file and is deliberately never accepted as an encryption flag.
func GenerateIdentity(path string) (string, error) {
	if !filepath.IsAbs(path) || keyfile.CheckDirectory(filepath.Dir(path)) != nil {
		return "", ErrFile
	}
	key, err := age.GenerateHybridIdentity()
	if err != nil {
		return "", ErrConfig
	}
	data := []byte(key.String() + "\n")
	defer clear(data)
	if err := writePrivate(path, data); err != nil {
		return "", ErrFile
	}
	return key.Recipient().String(), nil
}

type stagedFile struct {
	file        *os.File
	path, final string
	published   bool
	info        os.FileInfo
}

func stage(final string) (*stagedFile, error) {
	if !filepath.IsAbs(final) || keyfile.CheckDirectory(filepath.Dir(final)) != nil {
		return nil, ErrFile
	}
	if _, err := os.Lstat(final); !os.IsNotExist(err) {
		return nil, ErrFile
	}
	path := filepath.Join(filepath.Dir(final), ".recovery-"+uuid.NewString()+".partial")
	f, err := keyfile.CreateFile(path)
	if err != nil {
		return nil, ErrFile
	}
	return &stagedFile{file: f, path: path, final: final}, nil
}

func (f *stagedFile) close() { f.file.Close(); os.Remove(f.path) }
func (f *stagedFile) publish() error {
	if err := f.file.Sync(); err != nil {
		return ErrFile
	}
	var err error
	f.info, err = f.file.Stat()
	if err != nil {
		return ErrFile
	}
	if err = f.file.Close(); err != nil {
		return ErrFile
	}
	// A hard link publishes only to an absent path without a rename-overwrite race.
	if err := os.Link(f.path, f.final); err != nil {
		return ErrFile
	}
	f.published = true
	if err := syncDirectory(filepath.Dir(f.final)); err != nil {
		f.unpublish()
		return ErrFile
	}
	return nil
}
func (f *stagedFile) unpublish() {
	if !f.published {
		return
	}
	current, err := os.Lstat(f.final)
	if err == nil && f.info != nil && os.SameFile(f.info, current) {
		os.Remove(f.final)
	}
}

func openArchive(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrFile
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > maxBackupBytes {
		return nil, ErrFile
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrFile
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Size() > maxBackupBytes {
		f.Close()
		return nil, ErrFile
	}
	return f, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func sortedKeys[T any](m map[string]T) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}

// writePrivate also supports empty configuration files and aggregate environment
// JSON larger than a single credential. Publication requires a complete synced file.
func writePrivate(path string, data []byte) error {
	if len(data) > maxRecoveryBytes {
		return ErrFile
	}
	f, err := stage(path)
	if err != nil {
		return err
	}
	defer f.close()
	if _, err := f.file.Write(data); err != nil {
		return ErrFile
	}
	if err := f.publish(); err != nil {
		f.unpublish()
		return err
	}
	return nil
}

func validDatabaseName(value string) bool {
	if len(value) == 0 || len(value) > 63 || !utf8.ValidString(value) {
		return false
	}
	return !strings.ContainsFunc(value, unicode.IsControl)
}
