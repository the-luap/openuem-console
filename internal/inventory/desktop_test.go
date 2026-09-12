package inventory_test

import (
	"testing"

	"github.com/open-uem/openuem-console/internal/inventory"
)

func TestDesktopInventoryPreservesMissingHardwareNumbers(t *testing.T) {
	f := newSoftwareFixture(t)
	read := func() *inventory.Desktop {
		t.Helper()
		page, err := inventory.ReadDesktop(t.Context(), f.db, f.permissions, "viewer", f.scope, f.id)
		if err != nil {
			t.Fatal(err)
		}
		return page
	}
	if got := read(); got.Hardware != nil {
		t.Fatal("invented hardware report", got.Hardware)
	}
	report, err := f.client.Computer.Create().SetOwnerID(f.id).SetModel("Incomplete hardware report").Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := read(); got.Hardware == nil || got.Hardware.Memory != nil || got.Hardware.Cores != nil {
		t.Fatal("missing hardware numbers became zero", got.Hardware)
	}
	if err = f.client.Computer.UpdateOneID(report.ID).SetMemory(0).SetProcessorCores(0).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := read(); got.Hardware == nil || got.Hardware.Memory == nil || *got.Hardware.Memory != 0 || got.Hardware.Cores == nil || *got.Hardware.Cores != 0 {
		t.Fatal("reported zero became missing", got.Hardware)
	}
	// Preserve the exact stored integer, including values above a browser's
	// safe integer range. The view can round GiB without changing this report.
	const memory uint64 = 9007199254740993
	if err = f.client.Computer.UpdateOneID(report.ID).SetMemory(memory).SetProcessorCores(8).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := read(); got.Hardware == nil || got.Hardware.Memory == nil || *got.Hardware.Memory != memory || got.Hardware.Cores == nil || *got.Hardware.Cores != 8 {
		t.Fatal("present hardware numbers changed", got.Hardware)
	}
	if err = f.client.Computer.UpdateOneID(report.ID).ClearMemory().SetProcessorCores(-1).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := read(); got.Hardware == nil || got.Hardware.Memory != nil || got.Hardware.Cores == nil || *got.Hardware.Cores != -1 {
		t.Fatal("independent missing memory or reported cores changed", got.Hardware)
	}
}
