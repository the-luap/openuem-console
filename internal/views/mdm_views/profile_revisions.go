package mdm_views

func ProfileRevisionHistoryPath(profile string) string {
	if profile == "" {
		return "/ios/configurations/history"
	}
	return "/ios/configurations/" + profile + "/history"
}

func ProfileRevisionOrigin(origin string) string {
	switch origin {
	case "migration":
		return "Existing revision captured during migration"
	case "restore":
		return "Restored as a new revision"
	case "save":
		return "Saved revision"
	default:
		return "Origin unavailable"
	}
}
