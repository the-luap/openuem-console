//go:build linux || windows

package common_test

import (
	"strings"
	"testing"

	openuem "github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/common"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/setup/administrator"
)

func TestProtectedAdministratorCannotFallBackOrReset(t *testing.T) {
	w := &common.Worker{Model: &models.Model{}, IndividualAgentService: &openuem.ServiceConnection{}}
	if err := w.InitializeAdministrator(); err == nil || !strings.Contains(err.Error(), "requires protected") {
		t.Fatal("missing protected configuration reached the legacy account initializer", err)
	}
	w.ProtectedAdministrator = &administrator.Config{UserID: "first-admin"}
	w.ResetOpenUEMUser = true
	if err := w.InitializeAdministrator(); err == nil || !strings.Contains(err.Error(), "cannot reset") {
		t.Fatal("protected bootstrap could reset an account", err)
	}
	w.ResetOpenUEMUser = false
	if err := w.InitializeAdministrator(); err == nil || !strings.Contains(err.Error(), "database is unavailable") {
		t.Fatal("missing database was ignored", err)
	}
}
