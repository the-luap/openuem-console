package recovery

// File content is flushed before hard-link publication. Windows does not expose
// the Unix directory-fsync contract through os.File; namespace durability across
// power loss depends on the filesystem. Always verify a recovered backup pair.
func syncDirectory(string) error { return nil }
