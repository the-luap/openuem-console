package apple

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOSObservationsPreservePacketProvenanceAndPartialReportUncertainty(t *testing.T) {
	s, _, _, d := profileAssignmentAccessFixture(t)
	ctx := t.Context()
	read := func() (string, string, string, time.Time) {
		t.Helper()
		var version, build, source string
		var at time.Time
		require.NoError(t, s.db.QueryRow(`SELECT version,build,source,recorded_at FROM mdm_apple_os_observations WHERE device_id=$1`, d.ID).Scan(&version, &build, &source, &at))
		return version, build, source, at
	}
	version, build, source, _ := read()
	require.Equal(t, "18.6.2", version)
	require.Equal(t, "22G100", build)
	require.Equal(t, "device_information", source)
	osReport := func(fields map[string]any) *StatusReport {
		return &StatusReport{StatusItems: map[string]any{"device": map[string]any{"operating-system": fields}}}
	}
	complete := osReport(map[string]any{"version": "18.7.1", "build-version": "22H100"})
	require.NoError(t, s.saveStatus(ctx, d, complete))
	version, build, source, at := read()
	require.Equal(t, "18.7.1", version)
	require.Equal(t, "22H100", build)
	require.Equal(t, "declarative_status", source)
	require.NoError(t, s.saveStatus(ctx, d, &StatusReport{StatusItems: map[string]any{"softwareupdate": map[string]any{"install-state": "idle"}}}))
	_, sameBuild, _, sameTime := read()
	require.Equal(t, build, sameBuild)
	require.True(t, at.Equal(sameTime))
	require.NoError(t, s.saveStatus(ctx, d, osReport(map[string]any{"version": "18.7.1"})))
	version, build, _, at = read()
	require.Equal(t, "18.7.1", version)
	require.Empty(t, build)
	// The legacy merged inventory still retains its previous build. Cohort
	// evidence must not treat that value as part of the fresh version packet.
	current, err := s.Device(ctx, Scope{TenantID: 1, SiteID: 1}, d.ID)
	require.NoError(t, err)
	require.Equal(t, "22H100", current.BuildVersion)
	require.NoError(t, s.saveStatus(ctx, d, osReport(map[string]any{"build-version": "22H101"})))
	_, build, _, sameTime = read()
	require.Empty(t, build)
	require.True(t, at.Equal(sameTime))
	for _, report := range []*StatusReport{
		{StatusItems: map[string]any{}, FullReport: true},
		{StatusItems: map[string]any{"device": nil}},
		{StatusItems: map[string]any{"device": map[string]any{"operating-system": nil}}},
		osReport(map[string]any{"version": nil}),
		{StatusItems: complete.StatusItems, Errors: []map[string]any{{"StatusItem": "owned-error"}}},
		osReport(map[string]any{"version": "invalid"}),
	} {
		require.NoError(t, s.saveStatus(ctx, d, complete))
		require.NoError(t, s.saveStatus(ctx, d, report))
		var count int
		require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_os_observations WHERE device_id=$1`, d.ID).Scan(&count))
		require.Zero(t, count)
	}
}

func TestOSObservationRollsBackWithItsProtocolStatus(t *testing.T) {
	s, permissions, _, d := profileAssignmentAccessFixture(t)
	ctx := t.Context()
	policy := ownedUpdatePlanDefinition().Policy()
	require.NoError(t, s.SetUpdatePolicyWithAccess(ctx, Scope{TenantID: 1, SiteID: 1}, []string{d.ID}, &policy, "operator", permissions))
	var beforeVersion string
	var before time.Time
	require.NoError(t, s.db.QueryRow(`SELECT version,recorded_at FROM mdm_apple_os_observations WHERE device_id=$1`, d.ID).Scan(&beforeVersion, &before))
	_, err := s.db.Exec(`CREATE FUNCTION owned_os_observation_status_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned protocol status failure'; END $$; CREATE TRIGGER owned_os_observation_status_failure BEFORE UPDATE ON mdm_apple_update_policies FOR EACH ROW EXECUTE FUNCTION owned_os_observation_status_failure()`)
	require.NoError(t, err)
	report := &StatusReport{StatusItems: map[string]any{"device": map[string]any{"operating-system": map[string]any{"version": "18.7.1", "build-version": "22H100"}}, "softwareupdate": map[string]any{"install-state": "installing"}}}
	require.Error(t, s.saveStatus(ctx, d, report))
	var afterVersion string
	var after time.Time
	require.NoError(t, s.db.QueryRow(`SELECT version,recorded_at FROM mdm_apple_os_observations WHERE device_id=$1`, d.ID).Scan(&afterVersion, &after))
	require.Equal(t, beforeVersion, afterVersion)
	require.True(t, before.Equal(after))
}
