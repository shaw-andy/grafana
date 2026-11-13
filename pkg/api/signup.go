package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/events"
	"github.com/grafana/grafana/pkg/infra/metrics"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	tempuser "github.com/grafana/grafana/pkg/services/temp_user"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/util"
	"github.com/grafana/grafana/pkg/web"
)

// maxPreAuthFormBodySize caps pre-auth form-shaped request bodies (signup, password reset, invite completion, login).
const maxPreAuthFormBodySize = 100 * 1024 // 100 KiB

// GET /api/user/signup/options
func (hs *HTTPServer) GetSignUpOptions(c *contextmodel.ReqContext) response.Response {
	return response.JSON(http.StatusOK, util.DynMap{
		"verifyEmailEnabled": hs.Cfg.VerifyEmailEnabled,
		"autoAssignOrg":      hs.Cfg.AutoAssignOrg,
	})
}

// POST /api/user/signup
func (hs *HTTPServer) SignUp(c *contextmodel.ReqContext) response.Response {
	c.Req.Body = http.MaxBytesReader(c.Resp, c.Req.Body, maxPreAuthFormBodySize)

	form := dtos.SignUpForm{}
	var err error
	if err = web.Bind(c.Req, &form); err != nil {
		return response.Error(http.StatusBadRequest, "bad request data", err)
	}
	if !hs.Cfg.AllowUserSignUp {
		return response.Error(http.StatusUnauthorized, "User signup is disabled", nil)
	}

	form.Email, err = ValidateAndNormalizeEmail(form.Email)
	if err != nil {
		return response.Error(http.StatusBadRequest, "Invalid email address", nil)
	}

	existing := user.GetUserByLoginQuery{LoginOrEmail: form.Email}
	_, err = hs.userService.GetByLogin(c.Req.Context(), &existing)
	if err == nil {
		return response.Error(http.StatusUnprocessableEntity, "User with same email address already exists", nil)
	}

	userID, err := identity.UserIdentifier(c.GetID())
	if err != nil {
		hs.log.Debug("Failed to parse user id", "err", err)
	}

	cmd := tempuser.CreateTempUserCommand{}
	cmd.OrgID = -1
	cmd.Email = form.Email
	cmd.Status = tempuser.TmpUserSignUpStarted
	cmd.InvitedByUserID = userID
	cmd.Code, err = util.GetRandomString(20)
	if err != nil {
		return response.Error(http.StatusInternalServerError, "Failed to generate random string", err)
	}
	cmd.RemoteAddr = c.RemoteAddr()

	if _, err := hs.tempUserService.CreateTempUser(c.Req.Context(), &cmd); err != nil {
		return response.Error(http.StatusInternalServerError, "Failed to create signup", err)
	}

	if err := hs.bus.Publish(c.Req.Context(), &events.SignUpStarted{
		Email: form.Email,
		Code:  cmd.Code,
	}); err != nil {
		return response.Error(http.StatusInternalServerError, "Failed to publish event", err)
	}

	metrics.MApiUserSignUpStarted.Inc()

	return response.JSON(http.StatusOK, util.DynMap{"status": "SignUpCreated"})
}

func (hs *HTTPServer) SignUpStep2(c *contextmodel.ReqContext) response.Response {
	c.Req.Body = http.MaxBytesReader(c.Resp, c.Req.Body, maxPreAuthFormBodySize)

	form := dtos.SignUpStep2Form{}
	if err := web.Bind(c.Req, &form); err != nil {
		return response.Error(http.StatusBadRequest, "bad request data", err)
	}
	if !hs.Cfg.AllowUserSignUp {
		return response.Error(http.StatusUnauthorized, "User signup is disabled", nil)
	}

	createUserCmd := user.CreateUserCommand{
		Email:    form.Email,
		Login:    form.Username,
		Name:     form.Name,
		Password: form.Password,
		OrgName:  form.OrgName,
	}

	var verification *tempuser.TempUserDTO
	if hs.Cfg.VerifyEmailEnabled {
		var rsp response.Response
		if verification, rsp = hs.verifyUserSignUpEmail(c.Req.Context(), form.Email, form.Code); rsp != nil {
			return rsp
		}
		createUserCmd.EmailVerified = true
	}

	usr, err := hs.userService.Create(c.Req.Context(), &createUserCmd)
	if err != nil {
		if errors.Is(err, user.ErrUserAlreadyExists) {
			return response.Error(http.StatusUnauthorized, "User with same email address already exists", nil)
		}

		return response.Error(http.StatusInternalServerError, "Failed to create user", err)
	}

	// publish signup event
	if err := hs.bus.Publish(c.Req.Context(), &events.SignUpCompleted{
		Email: usr.Email,
		Name:  usr.NameOrFallback(),
	}); err != nil {
		return response.Error(http.StatusInternalServerError, "Failed to publish event", err)
	}

	invites, rsp := hs.authorizedSignUpInvites(c.Req.Context(), form, verification)
	if rsp != nil {
		return rsp
	}

	apiResponse := util.DynMap{"message": "User sign up completed successfully", "code": "redirect-to-landing-page"}
	for _, invite := range invites {
		if err := hs.applyUserInvite(c.Req.Context(), usr, invite, false); err != nil {
			if errors.Is(err, tempuser.ErrTempUserNotFound) {
				continue
			}
			return response.Error(http.StatusInternalServerError, "Failed to apply invite", err)
		}
		apiResponse["code"] = "redirect-to-select-org"
	}

	err = hs.loginUserWithUser(usr, c)
	if err != nil {
		return response.Error(http.StatusInternalServerError, "failed to login user", err)
	}

	metrics.MApiUserSignUpCompleted.Inc()

	return response.JSON(http.StatusOK, apiResponse)
}

// authorizedSignUpInvites returns the pending invites the completed sign up is
// allowed to claim. A verified email address authorizes every pending invite
// for that address. Without verification, only the invite whose code was
// submitted is authorized, since the email address alone proves nothing.
func (hs *HTTPServer) authorizedSignUpInvites(ctx context.Context, form dtos.SignUpStep2Form, verification *tempuser.TempUserDTO) ([]*tempuser.TempUserDTO, response.Response) {
	if verification != nil {
		claimCmd := tempuser.UpdateTempUserStatusCommand{
			ID:             verification.ID,
			Code:           verification.Code,
			ExpectedStatus: tempuser.TmpUserSignUpStarted,
			Status:         tempuser.TmpUserCompleted,
		}
		if err := hs.tempUserService.UpdateTempUserStatus(ctx, &claimCmd); err != nil {
			if errors.Is(err, tempuser.ErrTempUserNotFound) {
				return nil, nil
			}
			return nil, response.Error(http.StatusInternalServerError, "Failed to update sign up status", err)
		}

		invitesQuery := tempuser.GetTempUsersQuery{Email: verification.Email, Status: tempuser.TmpUserInvitePending}
		invites, err := hs.tempUserService.GetTempUsersQuery(ctx, &invitesQuery)
		if err != nil {
			return nil, response.Error(http.StatusInternalServerError, "Failed to query database for invites", err)
		}
		return invites, nil
	}

	if form.Code == "" {
		return nil, nil
	}

	tempUser, err := hs.tempUserService.GetTempUserByCode(ctx, &tempuser.GetTempUserByCodeQuery{Code: form.Code})
	if err != nil {
		if errors.Is(err, tempuser.ErrTempUserNotFound) {
			return nil, nil
		}
		return nil, response.Error(http.StatusInternalServerError, "Failed to read temp user", err)
	}

	if !sameEmailAddress(tempUser.Email, form.Email) {
		return nil, nil
	}

	switch tempUser.Status {
	case tempuser.TmpUserInvitePending:
		return []*tempuser.TempUserDTO{tempUser}, nil
	case tempuser.TmpUserSignUpStarted:
		claimCmd := tempuser.UpdateTempUserStatusCommand{
			ID:             tempUser.ID,
			Code:           tempUser.Code,
			ExpectedStatus: tempuser.TmpUserSignUpStarted,
			Status:         tempuser.TmpUserCompleted,
		}
		if err := hs.tempUserService.UpdateTempUserStatus(ctx, &claimCmd); err != nil && !errors.Is(err, tempuser.ErrTempUserNotFound) {
			return nil, response.Error(http.StatusInternalServerError, "Failed to update sign up status", err)
		}
	}

	return nil, nil
}

func sameEmailAddress(a, b string) bool {
	normalizedA, err := ValidateAndNormalizeEmail(a)
	if err != nil {
		return false
	}
	normalizedB, err := ValidateAndNormalizeEmail(b)
	if err != nil {
		return false
	}
	return normalizedA != "" && strings.EqualFold(normalizedA, normalizedB)
}

func (hs *HTTPServer) verifyUserSignUpEmail(ctx context.Context, email string, code string) (*tempuser.TempUserDTO, response.Response) {
	query := tempuser.GetTempUserByCodeQuery{Code: code}

	tempUser, err := hs.tempUserService.GetTempUserByCode(ctx, &query)
	if err != nil {
		if errors.Is(err, tempuser.ErrTempUserNotFound) {
			return nil, response.Error(http.StatusNotFound, "Invalid email verification code", nil)
		}
		return nil, response.Error(http.StatusInternalServerError, "Failed to read temp user", err)
	}

	if tempUser.Status != tempuser.TmpUserSignUpStarted {
		return nil, response.Error(http.StatusNotFound, "Invalid email verification code", nil)
	}

	if tempUser.Email != email {
		return nil, response.Error(http.StatusNotFound, "Email verification code does not match email", nil)
	}

	return tempUser, nil
}
