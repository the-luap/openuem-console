package models

import (
	"context"
	"github.com/open-uem/ent/settings"
)

func (m *Model) IsSMTPConfigured() bool {
	s, err := m.Client.Settings.Query().Where(settings.Not(settings.HasTenant())).Select(settings.FieldSMTPServer, settings.FieldSMTPPort).Only(context.Background())
	return err == nil && s.SMTPServer != "" && s.SMTPPort > 0
}
