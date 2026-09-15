// Package taskexecution builds bounded single-task payloads without publishing
// commands, retaining secrets, mutating stored configuration or claiming success.
package taskexecution

import (
	"errors"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/tasksecrets"
	ansiblecfg "github.com/open-uem/openuem-ansible-config/ansible"
	"github.com/open-uem/openuem-console/internal/taskconfig"
	"gopkg.in/yaml.v3"
)

var (
	ErrUnsupported = errors.New("task family or platform cannot be run individually")
	ErrInvalid     = errors.New("task execution configuration is unavailable")
)

const MaxPayloadSize = 512 << 10

type Payload struct {
	Operation string
	Data      []byte
}

func Supported(kind task.Type, platform task.AgentType) bool {
	if platform == task.AgentTypeAny {
		return false
	}
	for _, supported := range manualTypes {
		if kind == supported {
			return (taskconfig.Config{TaskType: kind.String(), AgentsType: platform.String()}).Supported()
		}
	}
	return false
}

// Keep execution support explicit: adding an editor family does not silently
// authorize an empty or unimplemented command mapper.
var manualTypes = []task.Type{
	task.TypeWingetInstall, task.TypeWingetDelete,
	task.TypeAddRegistryKey, task.TypeRemoveRegistryKey, task.TypeUpdateRegistryKeyDefaultValue, task.TypeAddRegistryKeyValue, task.TypeRemoveRegistryKeyValue,
	task.TypeAddLocalUser, task.TypeRemoveLocalUser, task.TypeAddLocalGroup, task.TypeRemoveLocalGroup, task.TypeAddUsersToLocalGroup, task.TypeRemoveUsersFromLocalGroup,
	task.TypeMsiInstall, task.TypeMsiUninstall, task.TypePowershellScript,
	task.TypeAddUnixLocalUser, task.TypeRemoveUnixLocalUser, task.TypeAddUnixLocalGroup, task.TypeRemoveUnixLocalGroup, task.TypeUnixScript,
	task.TypeFlatpakInstall, task.TypeFlatpakUninstall,
	task.TypeBrewCaskInstall, task.TypeBrewCaskUninstall, task.TypeBrewCaskUpgrade, task.TypeBrewFormulaInstall, task.TypeBrewFormulaUninstall, task.TypeBrewFormulaUpgrade,
}

// Types returns an independent list suitable for bounded configuration-free
// source searches. Build still validates the actual locked source.
func Types(platform task.AgentType) []string {
	result := []string{}
	for _, kind := range manualTypes {
		if Supported(kind, platform) {
			result = append(result, kind.String())
		}
	}
	return result
}

// Build copies the supplied task before secret conversion. The caller must have
// already authorized and locked the exact source and destination.
func Build(current *ent.Task, masterKey string) (*Payload, error) {
	if current == nil || !Supported(current.Type, current.AgentType) {
		return nil, ErrUnsupported
	}
	if current.ID <= 0 || current.Version < 0 || current.Disabled || current.Edges.Profile == nil || current.Edges.Profile.ID <= 0 || !bounded(current) {
		return nil, ErrInvalid
	}
	copy := *current
	config := openuem.ProfileConfig{ProfileID: current.Edges.Profile.ID}
	result := &Payload{}
	switch current.AgentType {
	case task.AgentTypeWindows:
		value, err := windowsConfiguration(&copy, masterKey)
		if err != nil {
			return nil, ErrInvalid
		}
		if value == nil || len(value.Properties.Resources) == 0 {
			return nil, ErrUnsupported
		}
		config.WinGetConfig = value
		result.Operation = "windowstask"
	case task.AgentTypeLinux, task.AgentTypeMacos:
		value, err := ansiblePlaybook(&copy, masterKey)
		if err != nil {
			return nil, ErrInvalid
		}
		if value == nil || len(value.Tasks) == 0 {
			return nil, ErrUnsupported
		}
		config.AnsibleConfig = []*ansiblecfg.AnsiblePlaybook{value}
		result.Operation = "ansible"
	default:
		return nil, ErrUnsupported
	}
	data, err := yaml.Marshal(config)
	if err != nil || len(data) > MaxPayloadSize {
		return nil, ErrInvalid
	}
	result.Data = data
	return result, nil
}

func bounded(t *ent.Task) bool {
	if len(t.Edges.Profile.Name) > 2048 || !utf8.ValidString(t.Edges.Profile.Name) || strings.ContainsRune(t.Edges.Profile.Name, 0) {
		return false
	}
	fields := reflect.ValueOf(*t)
	total := 0
	for i := 0; i < fields.NumField(); i++ {
		value := fields.Field(i)
		if value.Kind() != reflect.String {
			continue
		}
		text := value.String()
		limit := 16384
		switch fields.Type().Field(i).Name {
		case "LocalUserSSHKeyPassphrase":
			limit = tasksecrets.MaxSSHStoredSize
		case "LocalUserPassword":
			limit = tasksecrets.MaxPasswordStoredSize
		case "Name":
			limit = 2048
		case "Script":
			limit = 128 << 10
		}
		if len(text) > limit || !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
			return false
		}
		total += len(text)
	}
	return total <= 256<<10
}

func legacyPassword(value, masterKey string) (string, error) {
	plain, err := tasksecrets.OpenPassword(value, masterKey)
	if err != nil {
		return "", ErrInvalid
	}
	return plain, nil
}
