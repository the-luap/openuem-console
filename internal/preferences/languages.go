package preferences

type Language struct{ Code, Name string }

// Languages names the existing bundled catalogs. New copy falls back to English.
func Languages() []Language {
	return []Language{{"en", "English"}, {"ca", "Catalan"}, {"fr", "French"}, {"de", "German"}, {"no", "Norwegian"}, {"pt", "Portuguese"}, {"es", "Spanish"}}
}

func ValidLanguage(code string) bool {
	if code == "" {
		return true
	}
	for _, language := range Languages() {
		if code == language.Code {
			return true
		}
	}
	return false
}
