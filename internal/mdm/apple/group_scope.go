package apple

func validAppleGroupSourceScope(source, target Scope) bool {
	return target.TenantID > 0 && target.SiteID > 0 && source.TenantID == target.TenantID && (source.SiteID == 0 || source.SiteID == target.SiteID)
}
