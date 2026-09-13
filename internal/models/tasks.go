package models

import (
	"context"

	ent "github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/taskconfig"
)

type TaskConfig = taskconfig.Config

func (m *Model) GetTasksById(taskID int) (*ent.Task, error) {
	return m.Client.Task.Query().WithProfile().Where(task.ID(taskID)).First(context.Background())
}

func (m *Model) GetTaskSensitiveInformation() ([]*ent.Task, error) {
	return m.Client.Task.Query().Select(task.FieldID, task.FieldLocalUserPassword).All(context.Background())
}

func (m *Model) UpdateLocalUserPassword(taskID int, password string) error {
	return m.Client.Task.UpdateOneID(taskID).SetLocalUserPassword(password).Exec(context.Background())
}
