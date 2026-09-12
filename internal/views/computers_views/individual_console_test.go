package computers_views_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/a-h/templ"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/agents_views"
	"github.com/open-uem/openuem-console/internal/views/computers_views"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func TestIndividualConsoleHidesInboundActions(t *testing.T) {
	if err := locales.Load(); err != nil {
		t.Fatal(err)
	}
	ctx, err := locales.WithLocale(context.Background(), "en")
	if err != nil {
		t.Fatal(err)
	}
	info := &partials.CommonInfo{TenantID: "1", SiteID: "1", Principal: access.Principal{UserID: "test-admin", Grants: []access.Grant{{Role: access.Administrator}}}}
	agent := &ent.Agent{ID: "test-device", AgentStatus: "Enabled", Os: "windows"}
	for _, disabled := range []bool{false, true} {
		info.EndpointInboundDisabled = disabled
		for _, tc := range []struct {
			component           templ.Component
			forbidden, retained string
		}{
			{computers_views.ComputersNavbar(agent.ID, "overview", "5900", false, info, "windows", false, "0.13.0"), "/remote-assistance", "/logical-disks"},
			{agents_views.AddActionsButton(agent, 0, false, info), "/logs", "/settings"},
		} {
			var rendered bytes.Buffer
			if err := tc.component.Render(ctx, &rendered); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(rendered.String(), tc.forbidden) == disabled {
				t.Fatal("inbound control visibility disagrees with deployment mode", disabled, tc.forbidden)
			}
			if !strings.Contains(rendered.String(), tc.retained) {
				t.Fatal("ordinary management control disappeared", tc.retained)
			}
		}
	}
}
