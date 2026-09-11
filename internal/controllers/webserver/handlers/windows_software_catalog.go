package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
)

func (h *Handler) WindowsSoftwareApproval(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if scope.SiteID != 0 {
		return echo.NewHTTPError(http.StatusForbidden, "Approve software from the organization scope")
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	kind := c.QueryParam("kind")
	if kind == "" {
		kind = "windows-winget"
	}
	if kind != "windows-winget" && kind != "windows-msi" && kind != "windows-exe" {
		return softwareFailure(apple.ErrWindowsSoftware)
	}
	return RenderView(c, mdm_views.WindowsSoftwareApproval(c, info, kind, uuid.NewString()))
}

func (h *Handler) PublishWindowsSoftware(c echo.Context) error {
	adeHeaders(c)
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	f, err := adeEnrollmentForm(c, "request_id", "kind", "name", "identifier", "version", "architecture", "minimum_os", "sha256", "source_url", "install_arguments", "msi_properties", "uninstall_url", "uninstall_sha256", "uninstall_arguments", "detection_kind", "product_code", "uninstall_key", "registry_view", "detection_version", "success_codes", "reboot_codes")
	if err != nil {
		return err
	}
	p := apple.WindowsSoftwareInput{Name: f.Get("name"), Identifier: f.Get("identifier"), Version: f.Get("version"), Kind: f.Get("kind"), Architecture: f.Get("architecture"), MinimumOS: f.Get("minimum_os"), SHA256: f.Get("sha256"), Detection: apple.WindowsSoftwareDetection{Kind: f.Get("detection_kind"), ProductCode: f.Get("product_code"), UninstallKey: f.Get("uninstall_key"), RegistryView: f.Get("registry_view"), Version: f.Get("detection_version")}}
	p.Execution = apple.WindowsSoftwareExecution{SourceURL: f.Get("source_url"), InstallArguments: softwareArgumentLines(f.Get("install_arguments")), UninstallURL: f.Get("uninstall_url"), UninstallSHA256: f.Get("uninstall_sha256"), UninstallArguments: softwareArgumentLines(f.Get("uninstall_arguments"))}
	if p.SuccessCodes, err = softwareExitCodes(f.Get("success_codes")); err != nil {
		return softwareFailure(err)
	}
	if p.RebootCodes, err = softwareExitCodes(f.Get("reboot_codes")); err != nil {
		return softwareFailure(err)
	}
	p.Execution.MSIProperties = map[string]string{}
	for _, line := range softwareArgumentLines(f.Get("msi_properties")) {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return softwareFailure(apple.ErrWindowsSoftware)
		}
		if _, duplicate := p.Execution.MSIProperties[key]; duplicate {
			return softwareFailure(apple.ErrWindowsSoftware)
		}
		p.Execution.MSIProperties[key] = value
	}
	v, err := h.Apple.PublishWindowsSoftware(c.Request().Context(), scope, f.Get("request_id"), p, h.appleActor(c), h.Access)
	if err != nil {
		return softwareFailure(err)
	}
	return appleRedirect(c, info, "/software/catalog/"+v.ID)
}

func softwareArgumentLines(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(strings.ReplaceAll(value, "\r\n", "\n"), "\n"), "\n")
}

func softwareExitCodes(value string) ([]uint32, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > 16 {
		return nil, apple.ErrWindowsSoftware
	}
	codes := make([]uint32, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		base := 10
		if strings.HasPrefix(part, "0x") {
			base = 16
			part = strings.TrimPrefix(part, "0x")
		}
		n, err := strconv.ParseUint(part, base, 32)
		if err != nil {
			return nil, apple.ErrWindowsSoftware
		}
		codes = append(codes, uint32(n))
	}
	return codes, nil
}
