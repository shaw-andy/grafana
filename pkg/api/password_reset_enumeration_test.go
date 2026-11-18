package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/notifications"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// Lengths match the reset-code layout in pkg/services/notifications/codes.go:
// 12-digit start, 6-digit validity window, 64-character HMAC, then a hex login.
const (
	resetCodeStartLen   = 12
	resetCodeMinutesLen = 6
	resetCodeHMACLen    = 64
	resetCodePrefixLen  = resetCodeStartLen + resetCodeMinutesLen + resetCodeHMACLen
)

// placeholderPassword is the new password an unauthenticated caller submits.
// It is not a stored credential.
const placeholderPassword = "placeholder-password"

// forgedResetCode builds a code whose prefix parses as a time-limit code and
// whose signature does not match, with the guessed login hex-encoded in the tail.
func forgedResetCode(t *testing.T, login string) string {
	t.Helper()

	prefix := "202601011200" + "000120" + strings.Repeat("0", resetCodeHMACLen)
	require.Len(t, prefix, resetCodePrefixLen)

	return prefix + hex.EncodeToString([]byte(login))
}

func TestResetPasswordForgedCodeDoesNotRevealWhetherLoginExists(t *testing.T) {
	cfg := setting.NewCfg()
	// Shipped defaults: login and the login form are enabled.
	cfg.DisableLogin = false
	cfg.DisableLoginForm = false
	cfg.SecretKey = "placeholder-secret"

	sqlStore := db.NewTestStore(t)
	orgSvc, err := orgimpl.ProvideService(legacysql.NewDatabaseProvider(sqlStore), cfg, quotatest.New(false, nil))
	require.NoError(t, err)
	userSvc, err := userimpl.ProvideService(
		legacysql.NewDatabaseProvider(sqlStore), orgSvc, cfg, nil, nil, tracing.InitializeTracerForTest(),
		quotatest.New(false, nil), supportbundlestest.NewFakeBundleService(), nil,
	)
	require.NoError(t, err)

	// Real code validation. ProvideService also loads mail templates, which this path does not use.
	notificationSvc := &notifications.NotificationService{Cfg: cfg}

	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = cfg
		hs.userService = userSvc
		hs.NotificationService = notificationSvc
	})

	cases := []struct {
		name         string
		existing     string
		createLogin  string
		createEmail  string
		missingLogin string
	}{
		{
			name:         "login",
			existing:     "local-user",
			createLogin:  "local-user",
			createEmail:  "local-user@example.com",
			missingLogin: "missing-user",
		},
		{
			name:         "email",
			existing:     "person@example.com",
			createLogin:  "person",
			createEmail:  "person@example.com",
			missingLogin: "missing@example.com",
		},
		{
			name:         "mixed-case login",
			existing:     "MixedCase",
			createLogin:  "MixedCase",
			createEmail:  "mixedcase@example.com",
			missingLogin: "missing-mixed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			created, err := userSvc.Create(context.Background(), &user.CreateUserCommand{
				Login:    tc.createLogin,
				Email:    tc.createEmail,
				Name:     tc.createLogin,
				Password: user.Password(placeholderPassword),
			})
			require.NoError(t, err)

			before, err := userSvc.GetByLoginWithPassword(context.Background(), &user.GetUserByLoginQuery{LoginOrEmail: created.Login})
			require.NoError(t, err)

			known := postReset(t, server, forgedResetCode(t, tc.existing))
			unknown := postReset(t, server, forgedResetCode(t, tc.missingLogin))

			after, err := userSvc.GetByLoginWithPassword(context.Background(), &user.GetUserByLoginQuery{LoginOrEmail: created.Login})
			require.NoError(t, err)
			require.Equal(t, before.Password, after.Password, "forged code must not change the stored password")
			require.Equal(t, before.Salt, after.Salt)
			require.Equal(t, before.Rands, after.Rands)

			_, err = userSvc.GetByLoginWithPassword(context.Background(), &user.GetUserByLoginQuery{LoginOrEmail: tc.missingLogin})
			require.ErrorIs(t, err, user.ErrUserNotFound)

			require.Equalf(t, http.StatusBadRequest, known.status,
				"existing account %q: status %d message %q", tc.existing, known.status, known.message)
			require.Equalf(t, http.StatusBadRequest, unknown.status,
				"missing account %q: status %d message %q (existing account was status %d message %q)",
				tc.missingLogin, unknown.status, unknown.message, known.status, known.message)
			require.Equal(t, "Invalid or expired reset password code", known.message)
			require.Equal(t, known.message, unknown.message, "public error must not differ between an existing login and an unknown login")
			require.NotContains(t, known.raw, "user not found")
			require.NotContains(t, unknown.raw, "user not found")
		})
	}
}

type resetResponse struct {
	status  int
	message string
	raw     string
}

func postReset(t *testing.T, server *webtest.Server, code string) resetResponse {
	t.Helper()

	payload, err := json.Marshal(dtos.ResetUserPasswordForm{
		Code:            code,
		NewPassword:     user.Password(placeholderPassword),
		ConfirmPassword: user.Password(placeholderPassword),
	})
	require.NoError(t, err)

	req := server.NewPostRequest("/api/user/password/reset", bytes.NewReader(payload))
	req.Header.Del("Authorization")
	req.Header.Del("Cookie")

	resp, err := server.SendJSON(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var body struct {
		Message string `json:"message"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))

	return resetResponse{status: resp.StatusCode, message: body.Message, raw: string(raw)}
}
