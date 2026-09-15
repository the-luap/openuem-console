package common

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/open-uem/openuem-console/internal/setup/administrator"
	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

func (w *Worker) validateAdministratorReset() error {
	if w.ProtectedAdministrator != nil && w.ResetOpenUEMUser {
		return errors.New("protected first-administrator setup cannot reset an existing account")
	}
	return nil
}

func (w *Worker) InitializeAdministrator() error {
	if err := w.validateAdministratorReset(); err != nil {
		return err
	}
	if w.Model == nil {
		return errors.New("first-administrator database is unavailable")
	}
	if w.ProtectedAdministrator == nil {
		if w.IndividualAgentService != nil || w.InstallationID != "" {
			return errors.New("individual console requires protected first-administrator configuration")
		}
	}
	if w.Model.DB == nil {
		return errors.New("first-administrator database is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := secrets.CheckBinding(ctx, w.Model.DB, secrets.Runtime{Installation: w.InstallationID, JWT: w.JWTKey, Master: w.EncryptionMasterKey}); err != nil {
		return err
	}
	if w.ProtectedAdministrator == nil {
		return w.Model.CreateDefaultAdminPassword(w.ResetOpenUEMUser)
	}
	created, err := administrator.Initialize(ctx, w.Model.DB, *w.ProtectedAdministrator)
	if err != nil {
		return err
	}
	if created {
		log.Print("[INFO]: protected first-administrator account initialized")
	}
	return nil
}
