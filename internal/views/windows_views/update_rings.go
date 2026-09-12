package windows_views

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

type UpdateRingDraft struct {
	Form  url.Values                 `json:"-" xml:"-" yaml:"-"`
	Ring  windows.UpdateRingRevision `json:"-" xml:"-" yaml:"-"`
	Error string
}

func (UpdateRingDraft) String() string     { return "[protected Windows ring draft]" }
func (v UpdateRingDraft) GoString() string { return v.String() }

// Use the typed JSON field names so explicit zero and false survive an edit.
func UpdateRingFormValues(r windows.UpdateRingRevision, requestKey string) url.Values {
	form := url.Values{"ring_id": {r.RingID}, "request_key": {requestKey}, "expected_revision": {strconv.FormatInt(r.Revision, 10)}, "name": {r.Name}, "enabled": {strconv.FormatBool(r.Enabled)}}
	encoded, _ := json.Marshal(r.Policy)
	values := map[string]json.RawMessage{}
	_ = json.Unmarshal(encoded, &values)
	for _, field := range UpdatePolicyFields() {
		if value, ok := values[field.Name]; ok && string(value) != "null" {
			form.Set(field.Name, string(value))
		}
	}
	return form
}

func ringState(enabled bool) string {
	if enabled {
		return "Enabled"
	}
	return "Disabled"
}

func ringScope(info *partials.CommonInfo) string {
	tenant, _ := strconv.Atoi(info.TenantID)
	site, _ := strconv.Atoi(info.SiteID)
	return updateTargetScope(info, windows.DeviceMetadata{Scope: access.Scope{TenantID: tenant, SiteID: site}})
}

func ringRevisionAnchor(revision int64) string { return fmt.Sprintf("revision-%d", revision) }
