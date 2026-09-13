package mdm_views

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/views/locales"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/openuem-console/internal/views/tasks_views"
	"github.com/stretchr/testify/require"
)

func TestTaskEditingForms(t *testing.T) {
	ctx, err := locales.WithLocale(t.Context(), "en")
	require.NoError(t, err)
	for scope, info := range map[string]*partials.CommonInfo{"global": {TenantID: "-1", SiteID: "-1"}, "organization": {TenantID: "1", SiteID: "-1"}, "site": {TenantID: "1", SiteID: "2"}} {
		for _, kind := range []string{"script", "user", "unix-user", "netbird", "long"} {
			current := &ent.Task{ID: 27, Name: "Owned <edited> task", AgentType: task.AgentTypeWindows, Type: task.TypePowershellScript, Version: 7, Script: "Write-Output 'owned'", ScriptRun: task.ScriptRunAlways}
			review := &inventory.TaskEditReview{ProfileID: 17, Task: current}
			switch kind {
			case "user":
				current.Type = task.TypeAddLocalUser
				current.LocalUserUsername = "owned"
				review.PasswordSet = true
			case "unix-user":
				current.Type = task.TypeAddUnixLocalUser
				current.AgentType = task.AgentTypeLinux
				current.LocalUserUsername = "owned"
				review.PasswordSet = true
				review.PassphraseSet = true
			case "netbird":
				current.Type = task.TypeNetbirdRegister
				current.AgentType = task.AgentTypeAny
				current.NetbirdGroups = `"saved-ID"`
				current.NetbirdAllowExtraDNSLabels = true
			case "long":
				current.Name = strings.Repeat("界", 600)
			}
			var body bytes.Buffer
			body.WriteString(`<!doctype html><html lang="en" class="uk-theme-openuem"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/css/main.css"><script src="/assets/js/htmx.min.js" defer></script><script src="/assets/js/_hyperscript.min.js" defer></script></head><body class="bg-background text-foreground" hx-headers='{"X-CSRF-Token":"owned-csrf"}'><main id="main" class="p-4">`)
			require.NoError(t, tasks_views.TaskEditingForm(review, []nats.NetBirdGroups{{ID: "saved-ID", Name: "Saved group ID: saved-ID"}, {ID: "new-ID", Name: "Owned group"}}, info).Render(ctx, &body))
			body.WriteString(`</main></body></html>`)
			require.NotContains(t, body.String(), "MISSING")
			require.Contains(t, body.String(), `name="profile" value="17"`)
			require.Contains(t, body.String(), `name="task-version" value="7"`)
			if dir := os.Getenv("APPLE_MDM_UI_ARTIFACTS"); dir != "" {
				require.NoError(t, os.MkdirAll(dir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("task-editing-%s-%s.html", scope, kind)), body.Bytes(), 0644))
			}
		}
	}
}
