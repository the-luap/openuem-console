package desktop_views

import (
	"net/url"
	"strconv"

	"github.com/open-uem/openuem-console/internal/views/partials"
)

func inventoryCurrent(active, tab string) string {
	if active == tab {
		return "page"
	}
	return "false"
}

func softwareURL(info *partials.CommonInfo, id, search string, after int64) string {
	query := url.Values{}
	if search != "" {
		query.Set("q", search)
	}
	if after > 0 {
		query.Set("after", strconv.FormatInt(after, 10))
	}
	path := "/computers/" + url.PathEscape(id) + "/inventory/software"
	if len(query) != 0 {
		path += "?" + query.Encode()
	}
	return partials.GetNavigationUrl(info, path)
}
