package taskconfig

import "github.com/open-uem/ent/task"

// These are the legacy task families supported by the creation form and mapper.
func (c Config) Supported() bool {
	switch task.Type(c.TaskType) {
	case task.TypeWingetInstall, task.TypeWingetDelete, task.TypeAddRegistryKey, task.TypeRemoveRegistryKey, task.TypeUpdateRegistryKeyDefaultValue, task.TypeAddRegistryKeyValue, task.TypeRemoveRegistryKeyValue, task.TypeAddLocalUser, task.TypeRemoveLocalUser, task.TypeAddLocalGroup, task.TypeRemoveLocalGroup, task.TypeAddUsersToLocalGroup, task.TypeRemoveUsersFromLocalGroup, task.TypeMsiInstall, task.TypeMsiUninstall, task.TypePowershellScript:
		return c.AgentsType == task.AgentTypeWindows.String()
	case task.TypeAddUnixLocalUser, task.TypeRemoveUnixLocalUser, task.TypeAddUnixLocalGroup, task.TypeRemoveUnixLocalGroup, task.TypeUnixScript:
		return c.AgentsType == task.AgentTypeLinux.String() || c.AgentsType == task.AgentTypeMacos.String()
	case task.TypeFlatpakInstall, task.TypeFlatpakUninstall:
		return c.AgentsType == task.AgentTypeLinux.String()
	case task.TypeBrewCaskInstall, task.TypeBrewCaskUninstall, task.TypeBrewCaskUpgrade, task.TypeBrewFormulaInstall, task.TypeBrewFormulaUninstall, task.TypeBrewFormulaUpgrade:
		return c.AgentsType == task.AgentTypeMacos.String()
	case task.TypeNetbirdInstall, task.TypeNetbirdUninstall, task.TypeNetbirdRegister:
		return c.AgentsType == task.AgentTypeAny.String()
	}
	return false
}
