package inventory

import (
	"context"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestDeviceExportEncodingBoundsAndCancellation(t *testing.T) {
	entries := make([]DeviceEntry, 5000)
	for i := range entries {
		entries[i] = DeviceEntry{Kind: "desktop", ID: "owned", Name: strings.Repeat(`"`, 4000), Serial: strings.Repeat("x", 4000)}
	}
	for _, format := range []string{"csv", "json"} {
		data, err := encodeDeviceExport(t.Context(), entries, format)
		require.ErrorIs(t, err, ErrDeviceExportTooLarge)
		require.Nil(t, data)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	data, err := encodeDeviceExport(ctx, entries[:1], "json")
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, data)
}

func TestDeviceExportCapacityIsBounded(t *testing.T) {
	deviceExports <- struct{}{}
	defer func() { <-deviceExports }()
	deviceExports <- struct{}{}
	defer func() { <-deviceExports }()
	data, err := ExportDevices(t.Context(), nil, nil, "owned", access.Scope{TenantID: 1}, DeviceSources{}, DeviceFilter{}, "json")
	require.ErrorIs(t, err, ErrDeviceExportBusy)
	require.Nil(t, data)
}
