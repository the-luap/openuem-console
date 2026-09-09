package handlers

import (
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

func applePublicCertificateData(c echo.Context) ([]byte, error) {
	if c.Request().URL.RawQuery != "" || c.Request().URL.ForceQuery || c.Request().ParseMultipartForm(apple.MaxPublicCertificateBytes+8192) != nil {
		return nil, echo.NewHTTPError(400, "Invalid public certificate form")
	}
	form := c.Request().MultipartForm
	if form == nil {
		return nil, echo.NewHTTPError(400, "Select a public certificate file")
	}
	defer form.RemoveAll()
	allowed := map[string]bool{"csrf": true, "confirmed": true, "editor": true, "name": true, "identifier": true, "payload_scope": true}
	f := c.Request().PostForm
	for key, values := range f {
		if !allowed[key] || len(values) != 1 {
			return nil, echo.NewHTTPError(400, "Ambiguous public certificate form")
		}
	}
	if len(f["csrf"]) != 1 || f.Get("confirmed") != "yes" || f.Get("editor") != "apple-certificates" {
		return nil, echo.NewHTTPError(400, "Review the public certificate import")
	}
	if f.Get("payload_scope") != "System" && f.Get("payload_scope") != "User" {
		return nil, echo.NewHTTPError(400, "Select System or User certificate scope")
	}
	if len(form.File) != 1 || len(form.File["certificate"]) != 1 {
		return nil, echo.NewHTTPError(400, "Select exactly one PEM or DER certificate file")
	}
	data, err := readAppleUpload(c, "certificate", apple.MaxPublicCertificateBytes)
	if err != nil {
		return nil, appleFailure(err)
	}
	result, err := apple.BuildProfile(f.Get("name"), f.Get("identifier"), "apple-certificates", map[string]any{"PayloadScope": f.Get("payload_scope"), "CertificateData": data})
	if err != nil {
		return nil, appleFailure(err)
	}
	return result, nil
}
