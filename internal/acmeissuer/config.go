//go:build linux || darwin

// Package acmeissuer coordinates DNS-01 issuance and atomic gateway publication.
package acmeissuer

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/mail"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	ErrConfiguration = errors.New("ACME issuer configuration is invalid or inaccessible")
	ErrState         = errors.New("ACME issuer state is unavailable, changed or conflicts with this installation")
	ErrLocked        = errors.New("another issuer owns this state or publication directory")
	ErrIssuance      = errors.New("DNS-01 issuance failed; check the issuer configuration, provider credentials and connectivity")
	ErrPublication   = errors.New("the ACME result could not be validated and published; the previous generation is retained")
)

// Config contains operator-supplied configuration, never request parameters.
// Provider secrets remain in a separate protected JSON environment file.
type Config struct {
	Version                 int      `json:"version"`
	PublicOrigin            string   `json:"public_origin"`
	DirectoryURL            string   `json:"acme_directory_url"`
	Email                   string   `json:"email"`
	AcceptTerms             bool     `json:"accept_terms"`
	Provider                string   `json:"dns_provider"`
	ProviderEnvironmentFile string   `json:"provider_environment_file"`
	StateDirectory          string   `json:"state_directory"`
	PublicationDirectory    string   `json:"publication_directory"`
	ACMERootsFile           string   `json:"acme_roots_file,omitempty"`
	Resolvers               []string `json:"dns_resolvers,omitempty"`
	Profile                 string   `json:"certificate_profile,omitempty"`
	CheckInterval           string   `json:"check_interval,omitempty"`
	AttemptTimeout          string   `json:"attempt_timeout,omitempty"`
}

var (
	hostLabel       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	providerName    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	environmentName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,95}$`)
	profileName     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)
)

func ReadConfig(path string) (Config, error) {
	var config Config
	data, err := readProtected(path, 64<<10, true)
	if err != nil {
		return config, ErrConfiguration
	}
	defer clear(data)
	if decodeJSON(data, &config) != nil || config.Validate() != nil {
		return Config{}, ErrConfiguration
	}
	return config, nil
}

// CheckInputs validates local issuer inputs without opening state directories,
// acquiring leases, executing lego or contacting a provider. Provider-specific
// credential acceptance and retained account health require actual issuance.
func (c Config) CheckInputs(binary string) error {
	if c.Validate() != nil || !validExecutable(binary) {
		return ErrConfiguration
	}
	environment, err := c.providerEnvironment()
	clear(environment)
	return err
}

func decodeJSON(data []byte, target any) error {
	// encoding/json otherwise accepts repeated keys, including alternate casing
	// for struct fields. Reject ambiguous operator and retained-state documents.
	validation := json.NewDecoder(bytes.NewReader(data))
	validation.UseNumber()
	if uniqueJSONValue(validation, 0) != nil {
		return ErrConfiguration
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return ErrConfiguration
	}
	return nil
}

func uniqueJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrConfiguration
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			name = strings.ToLower(name)
			if err != nil || !ok || seen[name] {
				return ErrConfiguration
			}
			seen[name] = true
			if err := uniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrConfiguration
		}
	case json.Delim('['):
		for decoder.More() {
			if err := uniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return ErrConfiguration
		}
	}
	return nil
}

func (c Config) Validate() error {
	u, err := url.Parse(c.PublicOrigin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != c.PublicOrigin {
		return ErrConfiguration
	}
	hostname := u.Hostname()
	if len(hostname) > 253 || strings.Contains(hostname, ":") || net.ParseIP(hostname) != nil || !strings.Contains(hostname, ".") {
		return ErrConfiguration
	}
	for _, label := range strings.Split(hostname, ".") {
		if !hostLabel.MatchString(label) {
			return ErrConfiguration
		}
	}
	if u.Host != hostname && u.Host != hostname+":443" {
		return ErrConfiguration
	}
	u, err = url.Parse(c.DirectoryURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || len(c.DirectoryURL) > 2048 {
		return ErrConfiguration
	}
	if net.ParseIP(u.Hostname()) == nil {
		for _, label := range strings.Split(u.Hostname(), ".") {
			if !hostLabel.MatchString(label) {
				return ErrConfiguration
			}
		}
	}
	if port := u.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
			return ErrConfiguration
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return ErrConfiguration
	}
	email, err := mail.ParseAddress(c.Email)
	if err != nil || email.Address != c.Email || len(c.Email) > 240 || strings.ContainsAny(c.Email, "/\\") || !c.AcceptTerms || c.Version != 1 {
		return ErrConfiguration
	}
	if !providerName.MatchString(c.Provider) || c.Provider == "manual" || (c.Profile != "" && !profileName.MatchString(c.Profile)) {
		return ErrConfiguration
	}
	for _, path := range []string{c.StateDirectory, c.PublicationDirectory, c.ProviderEnvironmentFile} {
		if !cleanAbsolute(path) {
			return ErrConfiguration
		}
	}
	if c.ACMERootsFile != "" && (!cleanAbsolute(c.ACMERootsFile) || strings.Contains(c.ACMERootsFile, string(filepath.ListSeparator))) {
		return ErrConfiguration
	}
	if within(c.StateDirectory, c.PublicationDirectory) || within(c.PublicationDirectory, c.StateDirectory) {
		return ErrConfiguration
	}
	if within(c.PublicationDirectory, c.ProviderEnvironmentFile) {
		return ErrConfiguration
	}
	if len(c.Resolvers) > 4 {
		return ErrConfiguration
	}
	for _, resolver := range c.Resolvers {
		host, port, err := net.SplitHostPort(resolver)
		if err != nil || net.ParseIP(host) == nil || port == "" {
			return ErrConfiguration
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
			return ErrConfiguration
		}
	}
	if _, _, err = c.durations(); err != nil {
		return err
	}
	return nil
}

func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator) && !strings.ContainsRune(path, 0)
}

func within(parent, child string) bool {
	path, err := filepath.Rel(parent, child)
	return err == nil && (path == "." || (path != ".." && !strings.HasPrefix(path, ".."+string(filepath.Separator))))
}

func (c Config) durations() (time.Duration, time.Duration, error) {
	interval, timeout := 6*time.Hour, 15*time.Minute
	var err error
	if c.CheckInterval != "" {
		interval, err = time.ParseDuration(c.CheckInterval)
		if err != nil {
			return 0, 0, ErrConfiguration
		}
	}
	if c.AttemptTimeout != "" {
		timeout, err = time.ParseDuration(c.AttemptTimeout)
		if err != nil {
			return 0, 0, ErrConfiguration
		}
	}
	if interval < time.Minute || interval > 12*time.Hour || timeout < 10*time.Second || timeout > 30*time.Minute {
		return 0, 0, ErrConfiguration
	}
	return interval, timeout, nil
}

func (c Config) domain() string { u, _ := url.Parse(c.PublicOrigin); return u.Hostname() }

func (c Config) providerEnvironment() ([]string, error) {
	data, err := readProtected(c.ProviderEnvironmentFile, 64<<10, true)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer clear(data)
	var values map[string]string
	if decodeJSON(data, &values) != nil || len(values) == 0 || len(values) > 128 {
		return nil, ErrConfiguration
	}
	names := make([]string, 0, len(values))
	for name, value := range values {
		if !environmentName.MatchString(name) || len(value) == 0 || len(value) > 16<<10 || strings.ContainsRune(value, 0) || reservedEnvironment(name) {
			return nil, ErrConfiguration
		}
		if strings.HasSuffix(name, "_FILE") {
			if !cleanAbsolute(value) || within(c.PublicationDirectory, value) {
				return nil, ErrConfiguration
			}
			secret, err := readProtected(value, 64<<10, true)
			clear(secret)
			if err != nil {
				return nil, ErrConfiguration
			}
		}
		names = append(names, name)
	}
	sort.Strings(names)
	environment := make([]string, 0, len(names)+1)
	for _, name := range names {
		environment = append(environment, name+"="+values[name])
	}
	if c.ACMERootsFile != "" {
		roots, err := readProtected(c.ACMERootsFile, 1<<20, false)
		if err == nil {
			err = validateACMERoots(roots)
		}
		clear(roots)
		if err != nil {
			return nil, ErrConfiguration
		}
		environment = append(environment, "LEGO_CA_CERTIFICATES="+c.ACMERootsFile)
	}
	return environment, nil
}

func validateACMERoots(data []byte) error {
	certificates := 0
	for len(bytes.TrimSpace(data)) != 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) || certificates == 128 {
			return ErrConfiguration
		}
		ending := []byte("-----END CERTIFICATE-----")
		end := bytes.Index(data, ending)
		if end < 0 {
			return ErrConfiguration
		}
		end += len(ending)
		// Decode only the first complete block: pem.Decode may otherwise skip a
		// malformed earlier block and accept a later certificate silently.
		block, rest := pem.Decode(data[:end])
		if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return ErrConfiguration
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return ErrConfiguration
		}
		certificates++
		data = data[end:]
	}
	if certificates == 0 {
		return ErrConfiguration
	}
	return nil
}

func reservedEnvironment(name string) bool {
	if strings.HasPrefix(name, "LEGO_") || strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_") {
		return true
	}
	switch name {
	case "HOME", "PATH", "TMPDIR", "GODEBUG", "GOTRACEBACK", "GOMAXPROCS", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
		return true
	}
	return false
}
