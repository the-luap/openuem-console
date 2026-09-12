//go:build !linux && !darwin

package secrets

func supported() bool            { return false }
func syncDirectory(string) error { return ErrConfiguration }
