//go:build linux

package secrets

import "context"

// Exported only into test binaries for durable interruption fixtures.
func BootstrapDatabaseWithStepForTest(ctx context.Context, credentials, state string, config DatabaseConfig, step func(string) error) (Result, error) {
	return bootstrapDatabase(ctx, credentials, state, config, step)
}
