package mdm_views

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/require"
)

func TestAppleUpdateExceptionPages(t *testing.T) {
	ctx, err := locales.WithLocale(context.Background(), "en")
	require.NoError(t, err)
	sm := scs.New()
	ctx, err = sm.Load(ctx, "")
	require.NoError(t, err)
	sm.Put(ctx, "uid", "owned-operator")
	for _, state := range []string{"new", "active", "expired", "ended", "inactive", "no-notification", "receipt-pause", "receipt-resume", "history", "empty", "long"} {
		t.Run(state, func(t *testing.T) {
			info := &partials.CommonInfo{Principal: access.Principal{UserID: "owned-operator", Grants: []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}}, SM: &sessions.SessionManager{Manager: sm}, CSRFToken: "owned-csrf", TenantID: "1", SiteID: "1", CurrentVersion: "0.11.0", LatestVersion: "0.11.0", Tenants: []*ent.Tenant{{ID: 1, Description: "Owned organization"}}, Sites: []*ent.Site{{ID: 1, Description: "Berlin"}}}
			now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
			expires := now.Add(time.Hour)
			policy := &apple.UpdatePolicy{TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: "2026-10-01T18:00:00"}
			r := apple.UpdateException{ID: "60000000-0000-4000-8000-000000000001", Scope: apple.Scope{TenantID: 1, SiteID: 1}, DeviceID: "10000000-0000-4000-8000-000000000001", Revision: 1, Kind: "pause", Reason: "Owned <exception reason>", Actor: "owned-operator", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: &expires, PreviousPolicy: policy, NotificationAvailable: true, CommandID: "50000000-0000-4000-8000-000000000001"}
			p := apple.UpdateExceptionReview{Scope: r.Scope, DeviceID: r.DeviceID, Name: "Owned <exception phone>", Availability: "available", Policy: policy, NotificationAvailable: true, ReviewToken: strings.Repeat("a", 64), AssessedAt: now}
			switch state {
			case "active":
				p.Current, p.Policy = &r, nil
			case "expired":
				expires = now.Add(-time.Hour)
				p.Current, p.Policy = &r, nil
			case "ended":
				r.Kind, r.ExpiresAt, r.CommandID = "resume", nil, ""
				p.Current, p.Policy = &r, nil
			case "inactive":
				p.Availability = "identity_expired"
			case "no-notification":
				p.NotificationAvailable = false
			case "receipt-resume":
				r.Kind, r.ExpiresAt, r.CommandID, r.PreviousPolicy = "resume", nil, "", nil
			case "long":
				p.Name = strings.Repeat("N", 500) + "<script>"
				r.Reason = strings.Repeat("R", 1016) + "<script>"
				p.Current = &r
			}
			c := echo.New().NewContext(httptest.NewRequest("GET", "/tenant/1/site/1"+UpdateExceptionPath(r.DeviceID), nil).WithContext(ctx), httptest.NewRecorder())
			var body bytes.Buffer
			switch state {
			case "receipt-pause", "receipt-resume":
				err = AppleUpdateException(c, info, r).Render(ctx, &body)
			case "history":
				second := r
				second.ID = "60000000-0000-4000-8000-000000000002"
				second.Kind = "resume"
				second.Revision = 2
				err = AppleUpdateExceptions(c, info, r.DeviceID, []apple.UpdateException{second, r}, r.ID).Render(ctx, &body)
			case "empty":
				err = AppleUpdateExceptions(c, info, r.DeviceID, nil, "").Render(ctx, &body)
			default:
				err = AppleUpdateExceptionReview(c, info, p, "70000000-0000-4000-8000-000000000001", "70000000-0000-4000-8000-000000000002").Render(ctx, &body)
			}
			require.NoError(t, err)
			require.Contains(t, body.String(), "data-update-exception-page")
			require.NotContains(t, body.String(), r.Reason)
			require.NotContains(t, body.String(), p.Name)
			require.NotContains(t, body.String(), "@appleUpdate")
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "apple-update-exception-"+state+".html"), body.Bytes(), 0644))
			}
		})
	}
}
