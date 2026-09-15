package handlers

import (
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

func applePKCS12Data(c echo.Context) ([]byte, error) {
	if c.Request().URL.RawQuery != "" || c.Request().URL.ForceQuery || c.Request().ParseMultipartForm(apple.MaxPKCS12Bytes+8192) != nil {
		return nil, echo.NewHTTPError(400, "Invalid PKCS12 identity form")
	}
	form := c.Request().MultipartForm
	if form == nil {
		return nil, echo.NewHTTPError(400, "Select a PKCS12 identity file")
	}
	defer form.RemoveAll()
	allowed := map[string]bool{"csrf": true, "confirmed": true, "editor": true, "name": true, "identifier": true, "payload_scope": true, "password": true, "key_extractable": true, "all_apps_access": true}
	f := c.Request().PostForm
	for key, values := range f {
		if !allowed[key] || len(values) != 1 {
			return nil, echo.NewHTTPError(400, "Ambiguous PKCS12 identity form")
		}
	}
	if len(f["csrf"]) != 1 || f.Get("confirmed") != "yes" || f.Get("editor") != "apple-pkcs12" {
		return nil, echo.NewHTTPError(400, "Review the PKCS12 identity import")
	}
	if f.Get("payload_scope") != "System" && f.Get("payload_scope") != "User" {
		return nil, echo.NewHTTPError(400, "Select System or User certificate scope")
	}
	if len(form.File) != 1 || len(form.File["identity"]) != 1 {
		return nil, echo.NewHTTPError(400, "Select exactly one PKCS12 identity archive file")
	}
	data, err := readAppleUpload(c, "identity", apple.MaxPKCS12Bytes)
	if err != nil {
		return nil, appleFailure(c, err)
	}
	settings := map[string]any{"PayloadScope": f.Get("payload_scope"), "IdentityData": data, "Password": f.Get("password")}
	for field, key := range map[string]string{"key_extractable": "KeyIsExtractable", "all_apps_access": "AllowAllAppsAccess"} {
		switch f.Get(field) {
		case "":
		case "true", "false":
			settings[key] = f.Get(field) == "true"
		default:
			return nil, echo.NewHTTPError(400, "Select a valid PKCS12 key option")
		}
	}
	result, err := apple.BuildProfile(f.Get("name"), f.Get("identifier"), "apple-pkcs12", settings)
	if err != nil {
		return nil, appleFailure(c, err)
	}
	return result, nil
}
