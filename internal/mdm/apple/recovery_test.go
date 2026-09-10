package apple

import (
	"bytes"
	"errors"
	"testing"

	"github.com/open-uem/openuem-console/internal/testsupport/recoverydb"
	"github.com/open-uem/openuem-console/internal/testsupport/recoveryfixture"
)

func TestAppleRecoveryPreservesIdentityPushKeysAndProfileContinuity(t *testing.T) {
	db, source := recoverydb.New(t)
	s := initializeTestStore(t, db, "")
	settings := testSettings(t, s, 1)
	scope := Scope{TenantID: 1, SiteID: 1}
	d, certificate := testEnroll(t, s, scope, "Recovery phone")
	drainCommands(t, s, d, nil)
	payload, err := BuildProfile("Recovery passcode", "test.recovery.passcode", "passcode", map[string]any{"minLength": 6})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := s.SaveProfile(t.Context(), 1, "", 0, payload, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AssignProfile(t.Context(), scope, profile.ID, []string{d.ID}, "installed", "test-admin"); err != nil {
		t.Fatal(err)
	}
	target, environment := recoveryfixture.Cycle(t, source, map[string]string{"ENCRYPTION_MASTER_KEY": "integration-test-master-key-32-bytes-minimum"})
	restored, err := NewStore(target, environment["ENCRYPTION_MASTER_KEY"])
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	actual, err := restored.Settings(t.Context(), 1)
	if err != nil || actual.Topic != settings.Topic || !bytes.Equal(actual.CACertificate, settings.CACertificate) || !bytes.Equal(actual.PushKey, settings.PushKey) {
		t.Fatal("restore changed Apple authority or encrypted push key", err)
	}
	current, err := restored.AuthenticateCertificate(t.Context(), d.ID, certificate)
	if err != nil || current.ID != d.ID || current.UDID != d.UDID {
		t.Fatal("original Apple identity rejected after restore", err)
	}
	drainCommands(t, restored, current, []InstalledProfile{{Identifier: profile.Identifier, UUID: profile.UUID, Name: profile.Name, Managed: true}})
	assignments, err := restored.Assignments(t.Context(), scope, d.ID)
	if err != nil || len(assignments) != 1 || assignments[0].Status != "verified" {
		t.Fatal("restored profile did not finish its existing lifecycle", err)
	}
	if err := restored.AssignProfile(t.Context(), scope, profile.ID, []string{d.ID}, "removed", "test-admin"); err != nil {
		t.Fatal(err)
	}
	drainCommands(t, restored, current, []InstalledProfile{})
	assignments, err = restored.Assignments(t.Context(), scope, d.ID)
	if err != nil || len(assignments) != 1 || assignments[0].Status != "verified" || assignments[0].Desired != "removed" {
		t.Fatal("restored device lost profile removal", err)
	}
	wrong, err := NewStore(target, "wrong-restored-master-key-32-bytes-minimum")
	if err != nil {
		t.Fatal(err)
	}
	if value, err := wrong.Settings(t.Context(), 1); err == nil || value != nil {
		t.Fatal("recovery did not need the separately restored application key")
	}
	if _, err := restored.Device(t.Context(), Scope{TenantID: 2}, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("restored Apple device crossed organization")
	}
}
