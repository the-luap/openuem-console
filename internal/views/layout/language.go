package layout

import (
	"context"
	"github.com/invopop/ctxi18n"
)

func DocumentLanguage(ctx context.Context) string {
	if locale := ctxi18n.Locale(ctx); locale != nil {
		return string(locale.Code())
	}
	return "en"
}
