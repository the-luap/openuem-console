package handlers

import (
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/views/mdm_views"
)

func appleUserID(c echo.Context) (string, error) {
	id, err := uuid.Parse(c.Param("user"))
	if err != nil {
		return "", appleFailure(c, apple.ErrNotFound)
	}
	return id.String(), nil
}

func (h *Handler) AppleUser(c echo.Context) error {
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	userID, err := appleUserID(c)
	if err != nil {
		return err
	}
	d, err := h.Apple.Device(c.Request().Context(), scope, id)
	if err != nil {
		return appleFailure(c, err)
	}
	u, err := h.Apple.User(c.Request().Context(), scope, id, userID)
	if err != nil {
		return appleFailure(c, err)
	}
	detail := mdm_views.UserDetail{Device: d, User: u}
	detail.Commands, err = h.Apple.UserCommands(c.Request().Context(), scope, id, userID)
	if err != nil {
		return err
	}
	detail.Assignments, err = h.Apple.UserAssignments(c.Request().Context(), scope, id, userID)
	if err != nil {
		return err
	}
	detail.Profiles, err = h.Apple.Profiles(c.Request().Context(), scope.TenantID)
	if err != nil {
		return err
	}
	if err = h.Apple.RecordRead(c.Request().Context(), scope, h.appleActor(c), "user.inventory.read", id+"/"+userID); err != nil {
		return err
	}
	return renderApple(c, mdm_views.UserDetails(c, info, detail))
}

func (h *Handler) AppleUserAction(c echo.Context) error {
	info, scope, err := h.appleInfo(c)
	if err != nil {
		return err
	}
	if err = h.appleReady(); err != nil {
		return err
	}
	id, err := appleID(c)
	if err != nil {
		return err
	}
	userID, err := appleUserID(c)
	if err != nil {
		return err
	}
	actor := h.appleActor(c)
	switch appleRoute(c.Path()) {
	case "/ios/:id/users/:user/refresh":
		err = h.Apple.RefreshUserInventory(c.Request().Context(), scope, id, userID, actor)
	case "/ios/:id/users/:user/profiles":
		profileID, parseErr := uuid.Parse(c.FormValue("profile_id"))
		if parseErr != nil {
			return appleFailure(c, apple.ErrNotFound)
		}
		err = h.Apple.AssignUserProfile(c.Request().Context(), scope, id, userID, profileID.String(), c.FormValue("desired"), actor)
	case "/ios/:id/users/:user/commands/:command/retry":
		commandID, parseErr := uuid.Parse(c.Param("command"))
		if parseErr != nil {
			return appleFailure(c, apple.ErrNotFound)
		}
		err = h.Apple.RetryUserCommand(c.Request().Context(), scope, id, userID, commandID.String(), actor)
	case "/ios/:id/users/:user/pause":
		err = h.Apple.PauseUserManagement(c.Request().Context(), scope, id, userID, actor)
	case "/ios/:id/users/:user/resume":
		err = h.Apple.ResumeUserManagement(c.Request().Context(), scope, id, userID, actor)
	default:
		return echo.NewHTTPError(404)
	}
	if err != nil {
		return appleFailure(c, err)
	}
	return appleRedirect(c, info, "/ios/"+id+"/users/"+userID)
}
