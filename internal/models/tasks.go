package models

import (
	"context"
	"errors"

	ent "github.com/open-uem/ent"
	"github.com/open-uem/ent/profile"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/taskconfig"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

type TaskConfig = taskconfig.Config

func (m *Model) CountAllTasksForProfile(profileID int) (int, error) {
	return m.Client.Task.Query().Where(task.HasProfileWith(profile.ID(profileID))).Count(context.Background())
}

func (m *Model) GetTasksForProfileByPage(p partials.PaginationAndSort, profileID int) ([]*ent.Task, error) {
	if p.CurrentPage <= 0 || p.CurrentPage > 1000000 || p.PageSize <= 0 || p.PageSize > 1000 {
		return nil, errors.New("invalid task pagination")
	}
	offset := (p.CurrentPage - 1) * p.PageSize
	tasks, err := m.Client.Task.Query().Where(task.HasProfileWith(profile.ID(profileID))).Order(task.ByOrder(), task.ByID()).Limit(p.PageSize).Offset(offset).All(context.Background())
	if err != nil {
		return nil, err
	}
	// Display dense positions without writing legacy zero, duplicate or gapped orders on GET.
	for i, t := range tasks {
		t.Order = offset + i + 1
	}
	return tasks, nil
}

func (m *Model) GetTasksById(taskID int) (*ent.Task, error) {
	return m.Client.Task.Query().WithProfile().Where(task.ID(taskID)).First(context.Background())
}

func (m *Model) GetTaskSensitiveInformation() ([]*ent.Task, error) {
	return m.Client.Task.Query().Select(task.FieldID, task.FieldLocalUserPassword).All(context.Background())
}

func (m *Model) UpdateLocalUserPassword(taskID int, password string) error {
	return m.Client.Task.UpdateOneID(taskID).SetLocalUserPassword(password).Exec(context.Background())
}
