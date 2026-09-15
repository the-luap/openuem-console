// Command openuem-apple-profile-capabilities regenerates the checked-in channel
// capability facts from a pinned revision of Apple's device-management schemas.
package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type capability struct {
	Keys            []string `json:"keys,omitempty"`
	Introduced      string   `yaml:"introduced" json:"introduced"`
	Removed         string   `yaml:"removed" json:"removed,omitempty"`
	DeviceChannel   bool     `yaml:"devicechannel" json:"device_channel"`
	UserChannel     bool     `yaml:"userchannel" json:"user_channel"`
	Supervised      bool     `yaml:"supervised" json:"supervised,omitempty"`
	RequiresDEP     bool     `yaml:"requiresdep" json:"requires_dep,omitempty"`
	UserApprovedMDM bool     `yaml:"userapprovedmdm" json:"user_approved_mdm,omitempty"`
}

func main() {
	revision := flag.String("revision", "67045e2fa06f528b196c01edee6a8bf88b844beb", "Apple device-management commit (40 hexadecimal characters)")
	output := flag.String("output", "internal/mdm/apple/profile_capabilities.json", "generated JSON destination")
	flag.Parse()
	if err := generate(*revision, *output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(revision, output string) error {
	if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(revision) {
		return errors.New("revision must be a complete lowercase commit hash")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	response, err := client.Get("https://codeload.github.com/apple/device-management/zip/" + revision)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("schema download returned HTTP %d", response.StatusCode)
	}
	const limit = 32 << 20
	archive, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return err
	}
	if len(archive) > limit {
		return errors.New("schema archive exceeds 32 MiB")
	}
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return err
	}
	result := struct {
		Revision string                  `json:"revision"`
		MacOS    map[string][]capability `json:"macos"`
	}{revision, map[string][]capability{}}
	prefix := "device-management-" + revision + "/mdm/profiles/"
	for _, f := range reader.File {
		if !strings.HasPrefix(f.Name, prefix) || !strings.HasSuffix(f.Name, ".yaml") || strings.Contains(strings.TrimPrefix(f.Name, prefix), "/") {
			continue
		}
		if f.UncompressedSize64 > 4<<20 {
			return errors.New("profile schema exceeds 4 MiB")
		}
		r, err := f.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(r, (4<<20)+1))
		r.Close()
		if err != nil {
			return err
		}
		if len(data) > 4<<20 {
			return errors.New("profile schema exceeds 4 MiB")
		}
		var schema struct {
			Payload struct {
				Type string                `yaml:"payloadtype"`
				OS   map[string]capability `yaml:"supportedOS"`
			} `yaml:"payload"`
			Keys []struct {
				Key string `yaml:"key"`
			} `yaml:"payloadkeys"`
		}
		if err := yaml.Unmarshal(data, &schema); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		mac, ok := schema.Payload.OS["macOS"]
		if !ok || mac.Introduced == "" || mac.Introduced == "n/a" || schema.Payload.Type == "" {
			continue
		}
		for _, key := range schema.Keys {
			mac.Keys = append(mac.Keys, key.Key)
		}
		result.MacOS[schema.Payload.Type] = append(result.MacOS[schema.Payload.Type], mac)
	}
	if len(result.MacOS) < 50 {
		return errors.New("schema archive contains too few macOS payloads")
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(output), ".profile-capabilities-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Chmod(0644); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), output)
}
