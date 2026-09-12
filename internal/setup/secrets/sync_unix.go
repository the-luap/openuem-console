//go:build linux || darwin

package secrets

import "os"

func supported() bool { return true }

func syncDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return ErrState
	}
	defer file.Close()
	return file.Sync()
}
