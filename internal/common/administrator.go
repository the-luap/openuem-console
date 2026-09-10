package common

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/open-uem/openuem-console/internal/setup/administrator"
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
		if w.IndividualAgentService != nil {
			return errors.New("individual console requires protected first-administrator configuration")
		}
		return w.Model.CreateDefaultAdminPassword(w.ResetOpenUEMUser)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	created, err := administrator.Initialize(ctx, w.Model.DB, *w.ProtectedAdministrator)
	if err != nil {
		return err
	}
	if created {
		log.Print("[INFO]: protected first-administrator account initialized")
	}
	return nil
}
