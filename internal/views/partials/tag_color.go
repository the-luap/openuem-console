package partials

import (
	"github.com/a-h/templ"
	"github.com/open-uem/openuem-console/internal/tagcolor"
)

// Both resolved values contain only validated hexadecimal digits. Never pass
// arbitrary stored color strings to a style declaration or class constructor.
func TagColorStyle(value string) templ.SafeCSS {
	return templ.SafeCSS("background-color:" + tagcolor.Background(value) + ";color:" + tagcolor.Foreground(value) + ";")
}
