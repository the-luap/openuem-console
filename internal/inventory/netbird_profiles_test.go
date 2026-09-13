package inventory_test

import (
	"testing"

	nats "github.com/open-uem/nats"
	"github.com/open-uem/nats/netbirdstate"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/stretchr/testify/require"
)

func TestNetbirdObservedProfilesPreserveLabelsAndRejectFailedReports(t *testing.T) {
	f, _ := tagFixture(t)
	m := &models.Model{DB: f.db, Client: f.client}
	details := []nats.NetbirdProfile{{ID: "default", Name: "office, spaces", Active: true}, {ID: "a1b2c3d4", Name: "office, spaces"}}
	report := nats.Netbird{Installed: true, Version: "owned", ProfileDetails: details, Profiles: []string{"default", "a1b2c3d4"}}
	require.NoError(t, m.SaveNetbirdInfo(f.id, report))
	row, err := f.client.Netbird.Query().Only(t.Context())
	require.NoError(t, err)
	got, err := netbirdstate.Decode(row.ProfilesAvailable)
	require.NoError(t, err)
	require.Equal(t, details, got)
	for _, invalid := range []nats.Netbird{{Error: "owned collection failure"}, {ProfileDetails: []nats.NetbirdProfile{{ID: "same", Name: "first"}, {ID: "same", Name: "second"}}}} {
		require.Error(t, m.SaveNetbirdInfo(f.id, invalid))
		after, err := f.client.Netbird.Query().Only(t.Context())
		require.NoError(t, err)
		require.True(t, after.Installed)
		require.Equal(t, "owned", after.Version)
		require.Equal(t, row.ProfilesAvailable, after.ProfilesAvailable)
	}
	require.NoError(t, m.SaveNetbirdInfo(f.id, nats.Netbird{Installed: true, Profiles: []string{"legacy, literal"}}))
	row, err = f.client.Netbird.Query().Only(t.Context())
	require.NoError(t, err)
	got, err = netbirdstate.Decode(row.ProfilesAvailable)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "legacy, literal", got[0].Handle())
}
