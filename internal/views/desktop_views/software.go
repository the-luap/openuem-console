package desktop_views

import (
	"net/url"
	"strconv"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func inventoryCurrent(active, tab string) string {
	if active == tab {
		return "page"
	}
	return "false"
}

func inventoryLinkClass(active, tab string) string {
	if active == tab {
		return "uk-button uk-button-primary underline"
	}
	return "uk-button uk-button-default"
}

func softwareURL(info *partials.CommonInfo, id, search string, after int64) string {
	return inventoryReportURL(info, id, "software", search, after)
}

func networkURL(info *partials.CommonInfo, id, search string, after int64) string {
	return inventoryReportURL(info, id, "network", search, after)
}

func sharesURL(info *partials.CommonInfo, id, search string, after int64) string {
	return inventoryReportURL(info, id, "shares", search, after)
}

func memoryURL(info *partials.CommonInfo, id, search string, after int64) string {
	return inventoryReportURL(info, id, "memory", search, after)
}

func storageURL(info *partials.CommonInfo, id string, kind inventory.StorageKind, search string, after int64) string {
	path := inventoryReportURL(info, id, "storage", search, after)
	separator := "?"
	if search != "" || after > 0 {
		separator = "&"
	}
	return path + separator + "kind=" + url.QueryEscape(string(kind))
}

func peripheralsURL(info *partials.CommonInfo, id string, kind inventory.PeripheralsKind, search string, after int64) string {
	path := inventoryReportURL(info, id, "peripherals", search, after)
	separator := "?"
	if search != "" || after > 0 {
		separator = "&"
	}
	return path + separator + "kind=" + url.QueryEscape(string(kind))
}

func inventoryReportURL(info *partials.CommonInfo, id, report, search string, after int64) string {
	query := url.Values{}
	if search != "" {
		query.Set("q", search)
	}
	if after > 0 {
		query.Set("after", strconv.FormatInt(after, 10))
	}
	path := "/computers/" + url.PathEscape(id) + "/inventory/" + report
	if len(query) != 0 {
		path += "?" + query.Encode()
	}
	return partials.GetNavigationUrl(info, path)
}
