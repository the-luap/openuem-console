package models

import (
	"context"
	"testing"

	"github.com/open-uem/ent/enttest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SMTPTestSuite struct {
	suite.Suite
	t          enttest.TestingT
	model      Model
	settingsId int
}

func (suite *SMTPTestSuite) SetupTest() {
	client := enttest.Open(suite.T(), "sqlite3", "file:ent?mode=memory&_fk=1")
	suite.T().Cleanup(func() { client.Close() })
	suite.model = Model{Client: client}

	settings, err := suite.model.Client.Settings.Create().Save(context.Background())
	assert.NoError(suite.T(), err, "should create initial settings")
	suite.settingsId = settings.ID
}

func (suite *SMTPTestSuite) TestIsSMTPConfiguredRequiresOneGlobalSettingsRow() {
	assert.False(suite.T(), suite.model.IsSMTPConfigured())
	assert.NoError(suite.T(), suite.model.Client.Settings.UpdateOneID(suite.settingsId).SetSMTPServer("smtp.example.invalid").SetSMTPPort(587).Exec(context.Background()))
	assert.True(suite.T(), suite.model.IsSMTPConfigured())
	assert.NoError(suite.T(), suite.model.Client.Settings.Create().SetSMTPServer("second.example.invalid").Exec(context.Background()))
	assert.False(suite.T(), suite.model.IsSMTPConfigured())
}

func TestSMTPTestSuite(t *testing.T) {
	suite.Run(t, new(SMTPTestSuite))
}
