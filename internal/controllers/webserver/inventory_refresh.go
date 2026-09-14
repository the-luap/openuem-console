package webserver

import (
	"context"
	"log/slog"

	"github.com/open-uem/openuem-console/internal/inventory"
)

func (w *WebServer) startInventoryRefresh(ctx context.Context) error {
	w.inventoryMu.Lock()
	defer w.inventoryMu.Unlock()
	if w.inventoryCancel != nil {
		return nil
	}
	store, err := inventory.NewRefreshStore(w.Handler.Model.DB, w.Handler.Access, w.Handler.IndividualAgentService != nil, w.Handler.PublishInventoryReport)
	if err != nil {
		return err
	}
	if err = store.Migrate(ctx); err != nil {
		return err
	}
	if err = inventory.MigrateTaskSecrets(ctx, w.Handler.Model.DB, w.Handler.EncryptionMasterKey); err != nil {
		return err
	}
	manual, err := inventory.NewManualExecutionStore(w.Handler.Model.DB, w.Handler.Access, w.Handler.IndividualAgentService != nil, w.Handler.EncryptionMasterKey, w.Handler.PublishManualExecution)
	if err != nil {
		return err
	}
	w.Handler.InventoryRefresh = store
	w.Handler.ManualExecution = manual
	netbird, err := inventory.NewNetbirdOperationStore(w.Handler.Model.DB, w.Handler.Access, w.Handler.IndividualAgentService != nil, w.Handler.InspectNetbirdJournal, w.Handler.PublishNetbirdOperation)
	if err != nil {
		return err
	}
	w.Handler.NetbirdOperations = netbird
	resolution, err := inventory.NewNetbirdResolutionStore(netbird, w.Handler.RequestNetbirdControl)
	if err != nil {
		return err
	}
	w.Handler.NetbirdResolutions = resolution
	registration, err := inventory.NewNetbirdRegistrationStore(w.Handler.Model.DB, w.Handler.Access, w.Handler.IndividualAgentService != nil, w.Handler.EncryptionMasterKey, nil, w.Handler.RequestNetbirdControl, w.Handler.PublishNetbirdOperation)
	if err != nil {
		return err
	}
	w.Handler.NetbirdRegistrations = registration
	registrationResolution, err := inventory.NewNetbirdRegistrationResolutionStore(registration, w.Handler.RequestNetbirdControl)
	if err != nil {
		return err
	}
	w.Handler.NetbirdRegistrationResolutions = registrationResolution
	installation, err := inventory.NewNetbirdInstallationDeliveryStore(w.Handler.Model.DB, w.Handler.Access, w.Handler.IndividualAgentService != nil, w.Handler.EncryptionMasterKey, w.Handler.RequestNetbirdControl, w.Handler.PublishNetbirdPreparation, w.Handler.PublishNetbirdInstallation)
	if err != nil {
		return err
	}
	w.Handler.NetbirdInstallations = installation
	removal, err := inventory.NewNetbirdRemovalDeliveryStore(w.Handler.Model.DB, w.Handler.Access, w.Handler.IndividualAgentService != nil, w.Handler.RequestNetbirdControl, w.Handler.PublishNetbirdRemoval)
	if err != nil {
		return err
	}
	w.Handler.NetbirdRemovals = removal
	recovery, err := inventory.NewNetbirdRemovalRecoveryDeliveryStore(w.Handler.Model.DB, w.Handler.Access, w.Handler.IndividualAgentService != nil, w.Handler.RequestNetbirdControl, w.Handler.PublishNetbirdRemovalRecovery)
	if err != nil {
		return err
	}
	w.Handler.NetbirdRemovalRecoveries = recovery
	absence, err := inventory.NewNetbirdRemovalAbsenceDeliveryStore(w.Handler.Model.DB, w.Handler.Access, w.Handler.IndividualAgentService != nil, w.Handler.RequestNetbirdControl, w.Handler.PublishNetbirdRemovalAbsence)
	if err != nil {
		return err
	}
	w.Handler.NetbirdRemovalAbsences = absence

	run, cancel := context.WithCancel(context.Background())
	w.inventoryCancel = cancel
	w.inventoryDone = make(chan struct{})
	done := w.inventoryDone
	go func() {
		defer close(done)
		refreshDone := make(chan struct{})
		go func() { defer close(refreshDone); store.Run(run, slog.Default()) }()
		netbirdDone := make(chan struct{})
		go func() { defer close(netbirdDone); netbird.Run(run, slog.Default()) }()
		registrationDone := make(chan struct{})
		go func() { defer close(registrationDone); registration.Run(run, slog.Default()) }()
		installationDone := make(chan struct{})
		go func() { defer close(installationDone); installation.Run(run, slog.Default()) }()
		removalDone := make(chan struct{})
		go func() { defer close(removalDone); removal.Run(run, slog.Default()) }()
		recoveryDone := make(chan struct{})
		go func() { defer close(recoveryDone); recovery.Run(run, slog.Default()) }()
		absenceDone := make(chan struct{})
		go func() { defer close(absenceDone); absence.Run(run, slog.Default()) }()
		manual.Run(run, slog.Default())
		<-absenceDone
		<-recoveryDone
		<-removalDone
		<-installationDone
		<-registrationDone
		<-refreshDone
		<-netbirdDone
	}()
	return nil
}

func (w *WebServer) stopInventoryRefresh() {
	w.inventoryMu.Lock()
	cancel, done := w.inventoryCancel, w.inventoryDone
	w.inventoryMu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
