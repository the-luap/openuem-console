package windows_views

import (
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"net/url"
)

type CSPCommandDraft struct {
	Form    url.Values                 `json:"-" xml:"-" yaml:"-"`
	Preview *windows.CSPCommandPreview `json:"-" xml:"-" yaml:"-"`
	Error   string
}

func (CSPCommandDraft) String() string     { return "[protected Windows CSP command draft]" }
func (v CSPCommandDraft) GoString() string { return v.String() }
