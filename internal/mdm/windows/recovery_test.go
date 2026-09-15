package windows

import (
	"bytes"
	"testing"

	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/open-uem/openuem-console/internal/testsupport/recoverydb"
	"github.com/open-uem/openuem-console/internal/testsupport/recoveryfixture"
)

func TestWindowsRecoveryPreservesEnrollmentSessionAndCSPContinuity(t *testing.T) {
	db, source := recoverydb.New(t)
	base := initializeCredentialTestStore(t, db)
	if err := base.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	s, err := NewStoreWithMasterKey(db, authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	authority := initializeTestAuthority(t, s, 1)
	options := enrollmentTestOptions()
	invitation, request, _ := enrollmentTestRequest(t, s)
	originalResponse, err := s.EnrollWindows(t.Context(), request, options)
	if err != nil {
		t.Fatal(err)
	}
	result := readEnrollmentTestResult(t, s, invitation.ID)
	f := syncMLTestEnrolled(t, s, result, options)
	command := cspTestQueue(t, f, CSPCommandSpec{Kind: "Get", URI: "./DevDetail/SwV"})
	_, delivery := cspTestStart(t, f)
	audits, err := audit.NewStore(db, s.permissions)
	if err != nil {
		t.Fatal(err)
	}
	if err := audits.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	before, err := s.ExportCSPCommand(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, command.ID, cspTestRead(t, f, command.ID).Command.Revision, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before.Data)
	target, environment := recoveryfixture.Cycle(t, source, map[string]string{"WINDOWS_MDM_MASTER_KEY": authorityTestMasterKey})
	f.store, err = NewStoreWithMasterKey(target, environment["WINDOWS_MDM_MASTER_KEY"])
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	registered, err := audit.NewStore(target, f.store.permissions)
	if err != nil {
		t.Fatal(err)
	}
	if err := registered.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	current, err := f.store.EnrollmentAuthority(t.Context(), "admin", 1)
	if err != nil || current.ID != authority.ID || !bytes.Equal(current.Certificate, authority.Certificate) {
		t.Fatal("restore changed original Windows authority", err)
	}
	// The original device certificate and proof still authenticate after the
	// database and separately held master key have both been restored.
	identity, err := f.store.AuthenticateManagementDevice(managementTestRequest(t, result.Certificate, options), options)
	if err != nil || identity.DeviceID != f.identity.DeviceID {
		t.Fatal("restored Windows identity lost management", err)
	}
	replayed, err := f.store.EnrollWindows(t.Context(), request, options)
	if err != nil {
		t.Fatal("restored enrollment could not decrypt its exact retry", err)
	}
	provisioning, _ := provisioningFromResponse(t, replayed, request.MessageID)
	originalProvisioning, _ := provisioningFromResponse(t, originalResponse, request.MessageID)
	if len(provisioning) == 0 || !bytes.Equal(provisioning, originalProvisioning) {
		t.Fatal("restored bootstrap missing")
	}
	reply := syncMLTestWire(t, cspTestReply(syncMLTestParsed(t, delivery)))
	response, err := f.process(reply)
	if err != nil {
		t.Fatal("original CSP delivery could not complete after restore", err)
	}
	if replay, err := f.process(reply); err != nil || !bytes.Equal(replay, response) {
		t.Fatal("restored session lost exact packet retry", err)
	}
	completed := cspTestRead(t, f, command.ID)
	if completed.Command.Phase != "acknowledged" || len(completed.Outcomes) == 0 {
		t.Fatal("restored command lost result evidence")
	}
	if exported, err := f.store.ExportCSPCommand(t.Context(), "admin", f.identity.Scope, f.identity.DeviceID, command.ID, completed.Command.Revision, 0); err != nil || exported == nil {
		t.Fatal("restored protected evidence failed export", err)
	} else {
		clear(exported.Data)
	}
	if _, err := target.Exec(`DELETE FROM mdm_windows_csp_audit`); err == nil {
		t.Fatal("restore lost Windows audit immutability")
	}
}
