package apple

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/open-uem/nats/enrollment/keyfile"
)

var ErrVendorFiles = errors.New("vendor signing requires bounded public input files, a protected PKCS#8 RSA key and a new output file under trusted parents")

// SignVendorFiles is an offline operation for the vendor's own infrastructure.
// Only paths are arguments. The vendor key must never be supplied through flags,
// environment values or customer infrastructure. Parent directories remain the
// operator's trust responsibility; the existing keyfile reader enforces private
// access on the opened key file, and the writer never overwrites an entry.
func (v *VendorTrust) SignVendorFiles(csrPath, chainPath, keyPath, outputPath string) error {
	for _, path := range []string{csrPath, chainPath, keyPath, outputPath} {
		if !filepath.IsAbs(path) {
			return ErrVendorFiles
		}
	}
	csr, err := readVendorPublicFile(csrPath, 32<<10)
	if err != nil {
		return ErrVendorFiles
	}
	chain, err := readVendorPublicFile(chainPath, 64<<10)
	if err != nil {
		return ErrVendorFiles
	}
	// Validate public inputs and operator pins before opening the private key.
	if _, err = publicPushCSR(csr); err != nil {
		return err
	}
	if _, _, _, err = v.vendorChain(chain, time.Now()); err != nil {
		return err
	}
	key, err := loadVendorPrivateKey(keyPath)
	if err != nil {
		return ErrVendorFiles
	}
	result, err := v.SignVendorPortal(csr, chain, key, time.Now())
	if err != nil {
		return err
	}
	if err = keyfile.Create(outputPath, result.Encoded); err != nil {
		return ErrVendorFiles
	}
	return nil
}

func readVendorPublicFile(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > limit {
		return nil, ErrVendorFiles
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrVendorFiles
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) || info.Size() > limit {
		return nil, ErrVendorFiles
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		return nil, ErrVendorFiles
	}
	return data, nil
}

func loadVendorPrivateKey(path string) (*rsa.PrivateKey, error) {
	f, err := keyfile.Open(path, 32<<10)
	if err != nil {
		return nil, ErrVendorFiles
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (32<<10)+1))
	defer clear(data)
	if err != nil || len(data) > 32<<10 {
		return nil, ErrVendorFiles
	}
	if !bytes.HasPrefix(data, []byte("-----BEGIN PRIVATE KEY-----")) || bytes.Count(data, []byte("-----BEGIN")) != 1 {
		return nil, ErrVendorFiles
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrVendorFiles
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrVendorFiles
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.Validate() != nil {
		return nil, ErrVendorFiles
	}
	return key, nil
}
