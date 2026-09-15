package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/keyfile"
)

func TestReleaseCLIProtectedDatabaseSelectionAndArgumentPrivacy(t *testing.T) {
	t.Setenv("OPENUEM_AGENT_DATABASE_URL", "")
	t.Setenv("OPENUEM_AGENT_DATABASE_URL_FILE", filepath.Join(t.TempDir(), "missing.url"))
	var output bytes.Buffer
	for _, arguments := range [][]string{{"--unknown=synthetic-secret"}, {"--action", "show", "synthetic-secret"}} {
		if err := run(t.Context(), arguments, &output); err == nil || strings.Contains(err.Error(), "synthetic-secret") || output.Len() != 0 {
			t.Fatal("invalid release arguments were accepted or disclosed")
		}
	}
	if err := run(t.Context(), []string{"--actor", "synthetic-secret", "--help"}, &output); err != nil || !strings.Contains(output.String(), "-dburl-file") || strings.Contains(output.String(), "synthetic-secret") {
		t.Fatal("release help did not preserve argument privacy")
	}
	output.Reset()
	path := filepath.Join(t.TempDir(), "database.url")
	if err := keyfile.Create(path, []byte("postgres://synthetic:synthetic-secret@127.0.0.1:1/openuem?sslmode=disable")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	// Cancellation prevents network access. Reaching the database gate proves
	// the explicit protected file overrides an unavailable environment path.
	err := run(ctx, []string{"--dburl-file", path}, &output)
	if err == nil || err.Error() != "installer release database is unavailable" || output.Len() != 0 {
		t.Fatal("explicit protected release database selection failed", err)
	}
	t.Setenv("OPENUEM_AGENT_DATABASE_URL_FILE", path)
	if err := run(ctx, nil, &output); err == nil || err.Error() != "installer release database is unavailable" {
		t.Fatal("protected release database environment selection failed", err)
	}
	t.Setenv("OPENUEM_AGENT_DATABASE_URL", "synthetic-secret")
	if err := run(ctx, nil, &output); err == nil || strings.Contains(err.Error(), "synthetic-secret") || err.Error() != "configure one protected private agent database connection" {
		t.Fatal("conflicting release database sources were accepted or disclosed")
	}
}

func TestReleaseCLIOfflineInspectionIgnoresDatabaseConfiguration(t *testing.T) {
	t.Setenv("OPENUEM_AGENT_DATABASE_URL", "synthetic-secret")
	t.Setenv("OPENUEM_AGENT_DATABASE_URL_FILE", filepath.Join(t.TempDir(), "missing.url"))
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	content := []byte("non-executable release inspection fixture")
	digest := sha256.Sum256(content)
	now := time.Now().UTC()
	manifest := artifacts.Manifest{Schema: artifacts.Schema, Sequence: 1, Version: "0.12.0", PublishedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Artifacts: []artifacts.Artifact{{Platform: "windows", Architecture: "amd64", Format: "msi", Filename: "openuem-agent-0.12.0-windows-amd64.msi", Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])}}}
	data, err := artifacts.Sign(manifest, private, now)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := keyfile.Create(path, data); err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(t.TempDir(), "public.pem")
	if err := keyfile.Create(keys, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run(t.Context(), []string{"--action", "inspect", "--manifest", path, "--trusted-keys", keys, "--dburl-file", "unavailable-synthetic-input"}, &output); err != nil || !strings.Contains(output.String(), `"status":"candidate"`) || strings.Contains(output.String(), "synthetic-secret") {
		t.Fatal("offline release inspection accessed the database or failed signature verification", err)
	}
}
