package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/invopop/ctxi18n/i18n"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent"
	openuem_nats "github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/loginproof"
	"github.com/open-uem/openuem-console/internal/views/login_views"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/open-uem/utils"
	"github.com/pquerna/otp/totp"
)

func (h *Handler) Login(c echo.Context) error {
	// if accidentally we disable the use of certificates this allows us to reenable it again
	if h.ReenableCertAuth {
		if err := h.Model.ReEnableCertificatesAuth(); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, i18n.T(c.Request().Context(), "authentication.could_not_reenable_certs", err.Error()))
		}
	}

	// if accidentally we disable the use of passwords this allows us to reenable it again
	if h.ReenablePasswdAuth {
		if err := h.Model.ReEnablePasswdAuth(); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, i18n.T(c.Request().Context(), "authentication.could_not_reenable_passwd_auth", err.Error()))
		}
	}

	settings, err := h.Model.GetAuthenticationSettings()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, i18n.T(c.Request().Context(), "authentication.could_not_get_settings"))
	}

	// Destroy session if any
	if err := h.SessionManager.Manager.Destroy(c.Request().Context()); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	csrfToken, ok := c.Get("csrf").(string)
	if !ok || csrfToken == "" {
		return echo.NewHTTPError(http.StatusForbidden, i18n.T(c.Request().Context(), "authentication.csrf_token_not_found"))
	}

	// get Turnstile settings
	turnstileSiteKey, turnstileSecretKey, err := h.Model.GetTurnstileSettings()
	if err != nil {
		return echo.NewHTTPError(http.StatusForbidden, i18n.T(c.Request().Context(), "settings.turnstile_could_not_get_settings", err))
	}

	isTurnstileEnabled := turnstileSecretKey != "" && turnstileSiteKey != ""

	return RenderLogin(c, login_views.LoginIndex(login_views.Login(settings, turnstileSiteKey, turnstileSecretKey), csrfToken, isTurnstileEnabled))
}

func (h *Handler) LoginPasswordAuth(c echo.Context) error {
	username := c.FormValue("username")
	if username == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.username_empty"), true))
	}

	password := c.FormValue("password")
	if password == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.password_empty"), true))
	}

	// if CloudFlare Turnstile is used, check response
	tsSiteKey, tsSecretKey, err := h.Model.GetTurnstileSettings()
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "settings.turnstile_could_not_get_settings", err), true))
	}

	isTurnstileEnabled := tsSecretKey != "" && tsSiteKey != ""

	if isTurnstileEnabled {
		cfTurnStileResponse := c.FormValue("cf-turnstile-response")
		if cfTurnStileResponse == "" {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "settings.turnstile_challenge_not_found"), true))
		}
		if err := h.TurnstileCheckChallenge(c, cfTurnStileResponse, tsSecretKey); err != nil {
			return RenderError(c, partials.ErrorMessage(err.Error(), true))
		}
	}

	user, err := h.Model.GetUserById(username)
	if err != nil {
		log.Printf("[ERROR]: could not get user account for username %s, reason: %v", username, err)
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.wrong_username_or_password"), true))
	}

	if user.Hash == "" {
		log.Println("[ERROR]: hash is empty, maybe there was an issue with migration!")
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.wrong_username_or_password"), true))
	}

	// Check if passwords match
	match, err := argon2id.ComparePasswordAndHash(password, user.Hash)
	if err != nil {
		log.Printf("[ERROR]: could not compare password and hash for user %s, reason: %v", username, err)
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.wrong_username_or_password"), true))
	}

	if !match {
		h.AuthLogger.Printf("user %s entered a wrong password", username)
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.wrong_username_or_password"), true))
	}

	// Check if user is forced to change password
	if user.Register == openuem_nats.REGISTER_FORCE_PASSWORD_CHANGE {
		csrfToken, ok := c.Get("csrf").(string)
		if !ok || csrfToken == "" {
			return echo.NewHTTPError(http.StatusForbidden, i18n.T(c.Request().Context(), "authentication.csrf_token_not_found"))
		}

		// Create a session as we'll require the user to change the password
		if err := h.authorizePasswordReplacement(c, user, models.PasswordReplacementInitial, "", time.Time{}); err != nil {
			return err
		}

		return RenderLogin(c, login_views.LoginIndex(login_views.ChangePassword(tsSiteKey, tsSecretKey), csrfToken, isTurnstileEnabled))
	}

	if user.Use2fa {
		if err := h.NewSession(c, user); err != nil {
			log.Printf("[ERROR]: could not create a second-factor session: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "could not create session")
		}
		if user.TotpSecretConfirmed {
			return RenderLoginPartial(c, login_views.Use2FA(username, tsSiteKey, tsSecretKey))
		}
		return h.Register2FA(c)
	}

	return h.AccessGranted(c, user)
}

func (h *Handler) LoginPasswordChange(c echo.Context) error {
	proof, err := h.passwordReplacementProof(c)
	if err != nil {
		return err
	}
	username := h.SessionManager.Manager.GetString(c.Request().Context(), "uid")
	if username == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.username_empty"), true))
	}

	// if CloudFlare Turnstile is used, check response
	tsSiteKey, tsSecretKey, err := h.Model.GetTurnstileSettings()
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "settings.turnstile_could_not_get_settings", err), true))
	}

	isTurnstileEnabled := tsSecretKey != "" && tsSiteKey != ""

	if isTurnstileEnabled {
		cfTurnStileResponse := c.FormValue("cf-turnstile-response")
		if cfTurnStileResponse == "" {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "settings.turnstile_challenge_not_found"), true))
		}
		if err := h.TurnstileCheckChallenge(c, cfTurnStileResponse, tsSecretKey); err != nil {
			return RenderError(c, partials.ErrorMessage(err.Error(), true))
		}
	}

	password := c.FormValue("password")
	if password == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.password_empty"), true))
	}

	confirmPassword := c.FormValue("confirm-password")
	if confirmPassword == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.password_empty"), true))
	}

	if password != confirmPassword {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.passwords_dont_match"), true))
	}

	if err := ValidatePasswordComplexity(password); err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.password_complexity_invalid"), true))
	}

	if err := h.Model.ChangePasswordWithProof(c.Request().Context(), username, password, proof); err != nil {
		if errors.Is(err, models.ErrPasswordUnchanged) {
			return RenderError(c, partials.ErrorMessage("Choose a password different from the current password.", true))
		}
		log.Printf("[ERROR]: could not save the new password %s, reason: %v", username, err)
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.could_not_save_new_password"), true))
	}

	// Password has been changed
	h.AuthLogger.Printf("user %s has changed the password", username)

	// Redirect to login
	return h.Login(c)
}

func (h *Handler) Register2FA(c echo.Context) error {
	user, err := h.requirePrimaryAuthentication(c)
	if err != nil {
		return err
	}
	if user.TotpSecretConfirmed {
		return echo.NewHTTPError(http.StatusConflict, "Two-factor authentication is already enrolled.")
	}
	username := h.SessionManager.Manager.GetString(c.Request().Context(), "uid")
	if username == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.username_empty"), true))
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "OpenUEM",
		AccountName: username,
	})
	if err != nil {
		log.Printf("[ERROR]: could not generate totp key, reason: %v", err)
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.could_not_generate_totp_key"), true))
	}

	// Convert TOTP key into a PNG
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		log.Printf("[ERROR]: could not generate QR, reason: %v", err)
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.could_not_generate_qr"), true))
	}
	if err := png.Encode(&buf, img); err != nil {
		log.Printf("[ERROR]: could not encode image as PNG, reason: %v", err)
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.could_not_generate_qr"), true))
	}

	qrCode := base64.StdEncoding.EncodeToString(buf.Bytes())

	totpSecret := key.Secret()
	// encrypt the TOTP secret if we have the encryption master key
	if h.EncryptionMasterKey != "" {
		totpSecret, err = utils.EncryptSensitiveField(key.Secret(), h.EncryptionMasterKey)
		if err != nil {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_secret_cannot_be_encrypted"), true))
		}
	}

	if err := h.Model.SaveTOTPSecretKey(username, totpSecret); err != nil {
		log.Printf("[ERROR]: could not save TOTP secret key, reason: %v", err)
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_could_not_save_secret"), true))
	}

	return RenderLoginPartial(c, login_views.Register2FA(username, qrCode, key.Secret()))
}

func (h *Handler) LoginTOTPConfirm(c echo.Context) error {
	authorized, err := h.requirePrimaryAuthentication(c)
	if err != nil {
		return err
	}
	if authorized.TotpSecretConfirmed {
		return echo.NewHTTPError(http.StatusConflict, "Two-factor authentication is already enrolled.")
	}
	username := h.SessionManager.Manager.GetString(c.Request().Context(), "uid")
	if username == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.username_empty"), true))
	}

	passcode := c.FormValue("confirm-code")
	if passcode == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_empty_code"), true))
	}

	user, err := h.Model.GetUserById(username)
	if err != nil {
		log.Printf("[ERROR]: could not get user account for username %s, reason: %v", username, err)
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_wrong_setup"), true))
	}

	if h.EncryptionMasterKey != "" {
		isAccessTokenEncrypted, err := utils.IsSensitiveFieldEncrypted(user.TotpSecret, h.EncryptionMasterKey)
		if err != nil {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_secret_cannot_be_decrypted", err), true))
		}

		if isAccessTokenEncrypted {
			user.TotpSecret, err = utils.DecryptSensitiveField(user.TotpSecret, h.EncryptionMasterKey)
			if err != nil {
				return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_secret_cannot_be_decrypted", err), true))
			}
		}
	}

	valid := totp.Validate(passcode, user.TotpSecret)
	if !valid {
		log.Println("[ERROR]: the TOTP code is not valid")
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_wrong_setup"), true))
	}

	// Generate codes
	codes := []string{}
	for range 10 {
		code, err := generateRecoveryCode()
		if err != nil {
			log.Printf("[ERROR]: could not generate recovery codes, reason: %v", err)
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_wrong_setup"), true))
		}
		codes = append(codes, code)
	}

	// Save recovery codse
	if err := h.Model.SaveRecoveryCodes(username, codes); err != nil {
		log.Printf("[ERROR]: could not save recovery codes, reason: %v", err)
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_wrong_setup"), true))
	}

	// 2FA has been enabled
	h.AuthLogger.Printf("user %s has enabled 2FA", username)

	if err := h.completeUserSession(c, user, true); err != nil {
		return sessionAdmissionError(err, "Second-factor session could not be completed.")
	}

	// TODO - Get user's default tenant and site
	myTenant, err := h.Model.GetDefaultTenant()
	if err != nil {
		log.Printf("[ERROR]: could not get default tenant, reason: %v", err)
		return RenderError(c, partials.ErrorMessage(err.Error(), true))
	}

	mySite, err := h.Model.GetDefaultSite(myTenant)
	if err != nil {
		log.Printf("[ERROR]: could not get default site, reason: %v", err)
		return RenderError(c, partials.ErrorMessage(err.Error(), true))
	}

	u := fmt.Sprintf("%s/tenant/%d/site/%d/dashboard", h.consoleOrigin(), myTenant.ID, mySite.ID)

	return RenderLoginPartial(c, login_views.ShowRecoveryCodes(strings.Join(codes, "\n"), u))
}

func (h *Handler) LoginTOTPValidate(c echo.Context) error {
	authorized, err := h.requirePrimaryAuthentication(c)
	if err != nil {
		return err
	}
	if !authorized.TotpSecretConfirmed {
		return echo.NewHTTPError(http.StatusForbidden, "Complete two-factor enrollment before using an authentication code.")
	}
	username := h.SessionManager.Manager.GetString(c.Request().Context(), "uid")
	if username == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.username_empty"), true))
	}

	passcode := c.FormValue("confirm-code")
	if passcode == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_empty_code"), true))
	}

	// if CloudFlare Turnstile is used, check response
	tsSiteKey, tsSecretKey, err := h.Model.GetTurnstileSettings()
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "settings.turnstile_could_not_get_settings", err), true))
	}

	if tsSiteKey != "" && tsSecretKey != "" {
		cfTurnStileResponse := c.FormValue("cf-turnstile-response")
		if cfTurnStileResponse == "" {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "settings.turnstile_challenge_not_found"), true))
		}
		if err := h.TurnstileCheckChallenge(c, cfTurnStileResponse, tsSecretKey); err != nil {
			return RenderError(c, partials.ErrorMessage(err.Error(), true))
		}
	}

	user, err := h.Model.GetUserById(username)
	if err != nil {
		log.Printf("[ERROR]: could not get user account for username %s, reason: %v", username, err)
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_wrong_setup"), true))
	}

	if h.EncryptionMasterKey != "" {
		isAccessTokenEncrypted, err := utils.IsSensitiveFieldEncrypted(user.TotpSecret, h.EncryptionMasterKey)
		if err != nil {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_secret_cannot_be_decrypted", err), true))
		}

		if isAccessTokenEncrypted {
			user.TotpSecret, err = utils.DecryptSensitiveField(user.TotpSecret, h.EncryptionMasterKey)
			if err != nil {
				return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_secret_cannot_be_decrypted", err), true))
			}
		}
	}

	valid := totp.Validate(passcode, user.TotpSecret)
	if !valid {
		log.Println("[ERROR]: the TOTP code is not valid")
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_wrong_setup"), true))
	}

	// Access granted
	return h.AccessGranted(c, user)
}

func (h *Handler) LoginTOTPBackupRequest(c echo.Context) error {
	_, err := h.requirePrimaryAuthentication(c)
	if err != nil {
		return err
	}
	tsSiteKey, tsSecretKey, err := h.Model.GetTurnstileSettings()
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "settings.turnstile_could_not_get_settings", err), true))
	}

	return RenderLoginPartial(c, login_views.EnterRecoveryCode(tsSiteKey, tsSecretKey))
}

func (h *Handler) LoginTOTPBackupCheck(c echo.Context) error {
	authorized, err := h.requirePrimaryAuthentication(c)
	if err != nil {
		return err
	}
	if !authorized.TotpSecretConfirmed {
		return echo.NewHTTPError(http.StatusForbidden, "Complete two-factor enrollment before using an authentication code.")
	}
	// if CloudFlare Turnstile is used, check response
	tsSiteKey, tsSecretKey, err := h.Model.GetTurnstileSettings()
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "settings.turnstile_could_not_get_settings", err), true))
	}

	if tsSiteKey != "" && tsSecretKey != "" {
		cfTurnStileResponse := c.FormValue("cf-turnstile-response")
		if cfTurnStileResponse == "" {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "settings.turnstile_challenge_not_found"), true))
		}
		if err := h.TurnstileCheckChallenge(c, cfTurnStileResponse, tsSecretKey); err != nil {
			return RenderError(c, partials.ErrorMessage(err.Error(), true))
		}
	}

	username := h.SessionManager.Manager.GetString(c.Request().Context(), "uid")
	if username == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.username_empty"), true))
	}

	user, err := h.Model.GetUserById(username)
	if err != nil {
		log.Printf("[ERROR]: could not get user account for username %s, reason: %v", username, err)
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_wrong_setup"), true))
	}

	code := c.FormValue("recovery-code")
	if code == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_empty_code"), true))
	}

	isValid := h.Model.ConsumeRecoveryCode(username, code)
	if !isValid {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.totp_wrong_recovery_code"), true))
	}

	// Access granted
	return h.AccessGranted(c, user)
}

func (h *Handler) LoginForgotPass(c echo.Context) error {
	csrfToken, ok := c.Get("csrf").(string)
	if !ok || csrfToken == "" {
		return echo.NewHTTPError(http.StatusForbidden, i18n.T(c.Request().Context(), "authentication.csrf_token_not_found"))
	}

	// if CloudFlare Turnstile is used, check response
	tsSiteKey, tsSecretKey, err := h.Model.GetTurnstileSettings()
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "settings.turnstile_could_not_get_settings", err), true))
	}

	isTurnstileEnabled := tsSecretKey != "" && tsSiteKey != ""

	return RenderLogin(c, login_views.LoginIndex(login_views.LostPassword(tsSiteKey, tsSecretKey), csrfToken, isTurnstileEnabled))
}

func (h *Handler) NewSession(c echo.Context, user *ent.User) error {
	return h.establishUserSession(c, user, false, map[string]any{loginproof.SessionKey: loginproof.New(user.ID, loginproof.Password, user.Hash, time.Now())}, nil)
}

func (h *Handler) AccessGranted(c echo.Context, user *ent.User) error {
	if err := h.completeUserSession(c, user, user.Use2fa); err != nil {
		return sessionAdmissionError(err, "Sign-in session could not be completed.")
	}

	// TODO - Get user's default tenant and site
	myTenant, err := h.Model.GetDefaultTenant()
	if err != nil {
		log.Printf("[ERROR]: could not get default tenant, reason: %v", err)
		return RenderError(c, partials.ErrorMessage(err.Error(), true))
	}

	mySite, err := h.Model.GetDefaultSite(myTenant)
	if err != nil {
		log.Printf("[ERROR]: could not get default site, reason: %v", err)
		return RenderError(c, partials.ErrorMessage(err.Error(), true))
	}

	if h.AuthLogger != nil {
		if user.Passwd {
			if user.Use2fa {
				h.AuthLogger.Printf("user %s has logged in with a password and using 2FA", user.ID)
			} else {
				h.AuthLogger.Printf("user %s has logged in with a password", user.ID)
			}
		} else {
			if user.Use2fa {
				h.AuthLogger.Printf("user %s has logged in with a certificate and using 2FA", user.ID)
			}
		}
	}

	return c.Redirect(http.StatusFound, fmt.Sprintf("%s/tenant/%d/site/%d/dashboard", h.consoleOrigin(), myTenant.ID, mySite.ID))
}

func generateRecoveryCode() (string, error) {
	var charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	var randomCode string

	length := 16
	randomBytes := make([]byte, length)

	for i := range length {
		_, err := io.ReadFull(rand.Reader, randomBytes)
		if err != nil {
			return "", fmt.Errorf("failed to generate recovery code: %v", err)
		}
		randomIndex := int(randomBytes[i] % byte(len(charset)))
		randomCode += string(charset[randomIndex])
	}

	return fmt.Sprintf("%s-%s-%s-%s", randomCode[0:4], randomCode[4:8], randomCode[8:12], randomCode[12:16]), nil
}

func (h *Handler) ForgotPasswordEmail(c echo.Context) error {

	email := c.FormValue("email")
	if email == "" {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.email_empty"), true))
	}

	// if CloudFlare Turnstile is used, check response
	tsSiteKey, tsSecretKey, err := h.Model.GetTurnstileSettings()
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "settings.turnstile_could_not_get_settings", err), true))
	}

	if tsSiteKey != "" && tsSecretKey != "" {
		cfTurnStileResponse := c.FormValue("cf-turnstile-response")
		if cfTurnStileResponse == "" {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "settings.turnstile_challenge_not_found"), true))
		}
		if err := h.TurnstileCheckChallenge(c, cfTurnStileResponse, tsSecretKey); err != nil {
			return RenderError(c, partials.ErrorMessage(err.Error(), true))
		}
	}

	username := h.Model.GetUserIDByEmail(email)
	if username != "" {
		code, err := generateForgotCode()
		if err != nil {
			return err
		}

		hash, err := argon2id.CreateHash(code, argon2id.DefaultParams)
		if err != nil {
			return err
		}

		if err := h.Model.SaveForgotCode(username, hash); err != nil {
			return err
		}

		notification := openuem_nats.Notification{
			To:               email,
			Subject:          "Request to set a new password",
			MessageTitle:     "OpenUEM | Your code to create a new password",
			MessageText:      fmt.Sprintf("Here’s your confirmation code: %s. You can copy it into the open browser window or click the link below to confirm this request", code),
			MessageGreeting:  "You or someone else has indicated that you have forgotten your login password",
			MessageAction:    "Generate a new password",
			MessageActionURL: h.consoleOrigin() + fmt.Sprintf("/login/forgotverify?code=%s", code),
		}

		data, err := json.Marshal(notification)
		if err != nil {
			return err
		}

		if h.NATSConnection == nil || !h.NATSConnection.IsConnected() {
			return fmt.Errorf("%s", i18n.T(c.Request().Context(), "nats.not_connected"))
		}

		if err := h.PublishBroker("notification.confirm_email", data); err != nil {
			return err
		}

		user, err := h.Model.GetUserById(username)
		if err != nil {
			log.Printf("[ERROR]: could not get user account for username %s, reason: %v", username, err)
			return err
		}

		// Create a session as we'll require the username to change the password
		if err := h.CreateForgotPasswordSession(c, user); err != nil {
			return err
		}
	}

	return RenderLoginPartial(c, login_views.LostPasswordCode(email, tsSiteKey, tsSecretKey))
}

func (h *Handler) VerifyForgotPasswordCode(c echo.Context) error {
	confirmCode := ""
	if c.Request().Method == "GET" {
		confirmCode = c.QueryParam("code")
	}

	tsSiteKey, tsSecretKey, err := h.Model.GetTurnstileSettings()
	if err != nil {
		return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "settings.turnstile_could_not_get_settings", err), true))
	}

	isTurnstileEnabled := tsSecretKey != "" && tsSiteKey != ""

	if c.Request().Method == "POST" {
		confirmCode = c.FormValue("confirm-code")

		// if CloudFlare Turnstile is used, check response
		if tsSiteKey != "" && tsSecretKey != "" {
			cfTurnStileResponse := c.FormValue("cf-turnstile-response")
			if cfTurnStileResponse == "" {
				return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "settings.turnstile_challenge_not_found"), true))
			}
			if err := h.TurnstileCheckChallenge(c, cfTurnStileResponse, tsSecretKey); err != nil {
				return RenderError(c, partials.ErrorMessage(err.Error(), true))
			}
		}
	}

	username := h.SessionManager.Manager.GetString(c.Request().Context(), "uid")
	if username == "" {
		log.Println("[ERROR]: could not find a valid username in the session")
		if c.Request().Method == "GET" {
			return echo.NewHTTPError(http.StatusUnauthorized, i18n.T(c.Request().Context(), "login.forgot_verify_error"))
		} else {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.forgot_verify_error"), true))
		}
	}

	confirmCode = strings.ToUpper(confirmCode)
	if confirmCode == "" {
		if c.Request().Method == "GET" {
			return echo.NewHTTPError(http.StatusUnauthorized, i18n.T(c.Request().Context(), "login.forgot_code_empty"))
		} else {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.forgot_code_empty"), true))
		}
	}

	user, err := h.Model.GetUserById(username)
	valid := false
	if err == nil && user.ForgotPasswordCode != "" && user.ForgotPasswordCodeExpiresAt.After(time.Now()) {
		valid, err = argon2id.ComparePasswordAndHash(confirmCode, user.ForgotPasswordCode)
	}
	if err != nil || !valid {
		log.Print("[WARN]: password recovery proof rejected")
		return echo.NewHTTPError(http.StatusUnauthorized, "Password recovery authorization is invalid or expired.")
	}

	csrfToken, ok := c.Get("csrf").(string)
	if !ok || csrfToken == "" {
		return echo.NewHTTPError(http.StatusForbidden, i18n.T(c.Request().Context(), "authentication.csrf_token_not_found"))
	}

	if err := h.authorizePasswordReplacement(c, user, models.PasswordReplacementRecovery, models.PasswordReplacementDigest(user.ForgotPasswordCode), user.ForgotPasswordCodeExpiresAt); err != nil {
		return err
	}

	return RenderLogin(c, login_views.LoginIndex(login_views.ChangePassword(tsSiteKey, tsSecretKey), csrfToken, isTurnstileEnabled))
}

func (h *Handler) CreateForgotPasswordSession(c echo.Context, user *ent.User) error {
	return h.createPasswordReplacementSession(c, user, nil)
}

func (h *Handler) LoginNewUser(c echo.Context) error {
	// 1. Parse token
	tokenString := c.QueryParam("token")

	if tokenString == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, i18n.T(c.Request().Context(), "login.token_invalid"))
	}

	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(h.JWTKey), nil
	})

	if err != nil {
		return echo.NewHTTPError(http.StatusForbidden, "could not parse claims")
	}

	if claims, ok := token.Claims.(*MyCustomClaims); ok {
		// Is the token expired?
		if claims.ExpiresAt == nil || time.Now().After(claims.ExpiresAt.Time) {
			return echo.NewHTTPError(http.StatusForbidden, "token has expired, please contact your administrator to request a new email to set your initial password")
		}

		// Get user from database
		user, err := h.Model.GetUserById(claims.ID)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		invitationBinding := models.PasswordReplacementDigest(user.NewUserToken)
		// Check if token exists in database for this user
		if h.EncryptionMasterKey != "" {
			isNewUserTokenEncrypted, err := utils.IsSensitiveFieldEncrypted(user.NewUserToken, h.EncryptionMasterKey)
			if err != nil {
				return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.cannot_decrypt_new_user_token"), true))
			}

			if isNewUserTokenEncrypted {
				user.NewUserToken, err = utils.DecryptSensitiveField(user.NewUserToken, h.EncryptionMasterKey)
				if err != nil {
					return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "login.cannot_decrypt_new_user_token"), true))
				}
			}
		}

		if user.NewUserToken != tokenString {
			return echo.NewHTTPError(http.StatusForbidden, "token is not valid, please contact your administrator to request a new email to set your initial password")
		}

		// Create a session as we'll require the user to change the password
		csrfToken, ok := c.Get("csrf").(string)
		if !ok || csrfToken == "" {
			return echo.NewHTTPError(http.StatusForbidden, i18n.T(c.Request().Context(), "authentication.csrf_token_not_found"))
		}

		if err := h.authorizePasswordReplacement(c, user, models.PasswordReplacementInvitation, invitationBinding, claims.ExpiresAt.Time); err != nil {
			return err
		}

		// if CloudFlare Turnstile is used, check response
		tsSiteKey, tsSecretKey, err := h.Model.GetTurnstileSettings()
		if err != nil {
			return RenderError(c, partials.ErrorMessage(i18n.T(c.Request().Context(), "settings.turnstile_could_not_get_settings", err), true))
		}

		isTurnstileEnabled := tsSecretKey != "" && tsSiteKey != ""
		return RenderLogin(c, login_views.LoginIndex(login_views.ChangePassword(tsSiteKey, tsSecretKey), csrfToken, isTurnstileEnabled))

	} else {
		return echo.NewHTTPError(http.StatusBadRequest, "unknown claims type, cannot proceed")
	}
}

func generateForgotCode() (string, error) {
	var charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	var randomCode strings.Builder

	length := 6
	randomBytes := make([]byte, length)

	for i := range length {
		_, err := io.ReadFull(rand.Reader, randomBytes)
		if err != nil {
			return "", fmt.Errorf("failed to generate forgot password code: %v", err)
		}
		randomIndex := int(randomBytes[i] % byte(len(charset)))
		randomCode.WriteString(string(charset[randomIndex]))
	}

	return fmt.Sprintf("%s", randomCode.String()[0:6]), nil
}

// consoleOrigin uses trusted configuration, never request headers or a Referer.
func (h *Handler) consoleOrigin() string {
	if h.PublicOrigin != "" {
		return h.PublicOrigin
	}
	if h.ReverseProxyServer != "" {
		return "https://" + h.ReverseProxyServer
	}
	return fmt.Sprintf("https://%s:%s", h.ServerName, h.ConsolePort)
}
