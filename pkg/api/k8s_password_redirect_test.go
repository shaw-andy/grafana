package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/open-feature/go-sdk/openfeature"
	"github.com/open-feature/go-sdk/openfeature/memprovider"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	clientrest "k8s.io/client-go/rest"

	iamv0 "github.com/grafana/grafana/apps/iam/pkg/apis/iam/v0alpha1"
	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/registry/apis/iam/legacy"
	iamuser "github.com/grafana/grafana/pkg/registry/apis/iam/user"
	"github.com/grafana/grafana/pkg/services/apiserver"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/login/authinfotest"
	"github.com/grafana/grafana/pkg/services/loginattempt/loginattempttest"
	"github.com/grafana/grafana/pkg/services/notifications"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/team/teamtest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/web"
)

// Obvious placeholders. These are not credentials from any deployment.
const (
	originalLoginPassword    = "placeholder-original"
	replacementLoginPassword = "placeholder-replacement"
	wrongOldPassword         = "placeholder-wrong"
	emailCodeKeyPlaceholder  = "placeholder-email-code-key"
)

// TestKubernetesUsersRedirectPasswordUpdates covers the three password writes
// that call user.Service.Update: the signed-in change, reset completion, and
// the server-admin password update. With kubernetesUsersRedirect enabled, a
// success response must mean the password client accepts the replacement and
// rejects the previous one. A mismatched old password must not succeed.
func TestKubernetesUsersRedirectPasswordUpdates(t *testing.T) {
	h := newPasswordRedirectHarness(t)

	t.Run("legacy path still replaces the login password", func(t *testing.T) {
		disableKubernetesUsersRedirect(t)
		account := h.createAccount(t, "legacy-path")
		resp := h.changePassword(t, account, originalLoginPassword, replacementLoginPassword)
		requireSuccess(t, resp, "User password changed")
		h.requireLogin(t, account.Login, replacementLoginPassword, originalLoginPassword)
	})

	t.Run("signed-in password change", func(t *testing.T) {
		enableKubernetesUsersRedirect(t)
		account := h.createAccount(t, "signed-in-change")
		resp := h.changePassword(t, account, originalLoginPassword, replacementLoginPassword)
		requireSuccess(t, resp, "User password changed")
		h.requireLogin(t, account.Login, replacementLoginPassword, originalLoginPassword)
	})

	t.Run("signed-in change with the wrong old password", func(t *testing.T) {
		enableKubernetesUsersRedirect(t)
		account := h.createAccount(t, "signed-in-mismatch")
		resp := h.changePassword(t, account, wrongOldPassword, replacementLoginPassword)
		require.NotEqual(t, http.StatusOK, resp.Status(), string(resp.Body()))
		h.requireLogin(t, account.Login, originalLoginPassword, replacementLoginPassword)
	})

	t.Run("password reset completion", func(t *testing.T) {
		enableKubernetesUsersRedirect(t)
		account := h.createAccount(t, "password-reset")
		resp := h.resetPassword(t, account, replacementLoginPassword)
		requireSuccess(t, resp, "User password changed")
		h.requireLogin(t, account.Login, replacementLoginPassword, originalLoginPassword)
	})

	t.Run("server admin password update", func(t *testing.T) {
		enableKubernetesUsersRedirect(t)
		account := h.createAccount(t, "admin-update")
		resp := h.adminUpdatePassword(t, account, replacementLoginPassword)
		requireSuccess(t, resp, "User password updated")
		h.requireLogin(t, account.Login, replacementLoginPassword, originalLoginPassword)
	})
}

type passwordRedirectHarness struct {
	cfg      *setting.Cfg
	sql      db.DB
	users    user.Service
	legacy   user.Service
	hs       *HTTPServer
	store    *iamuser.LegacyStore
	password *clients.Grafana
	accounts map[int64]*user.User
}

func newPasswordRedirectHarness(t *testing.T) *passwordRedirectHarness {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.AutoAssignOrg = false
	cfg.DisableLogin = false
	cfg.DisableLoginForm = false
	cfg.EmailCodeValidMinutes = 120
	cfg.SecretKey = emailCodeKeyPlaceholder

	sqlStore := db.InitTestDB(t) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore
	require.NoError(t, sqlStore.WithDbSession(context.Background(), func(sess *db.Session) error {
		count, err := sess.Where("id = ?", 1).Count(&org.Org{})
		if err != nil || count > 0 {
			return err
		}
		now := time.Now()
		_, err = sess.Insert(&org.Org{ID: 1, Name: "Main Org", Created: now, Updated: now})
		return err
	}))

	h := &passwordRedirectHarness{
		cfg:      cfg,
		sql:      sqlStore,
		accounts: map[int64]*user.User{},
	}

	// Create inserts the org membership inside its own transaction. Doing that
	// write on a second session deadlocks SQLite, so record the membership after
	// Create commits.
	orgService := &orgtest.FakeOrgService{ExpectedOrgUserID: 1}

	server := httptest.NewServer(http.HandlerFunc(h.serveUserResource))
	t.Cleanup(server.Close)

	tracer := tracing.InitializeTracerForTest()
	userSvc, err := userimpl.ProvideService(
		legacysql.NewDatabaseProvider(sqlStore),
		orgService,
		cfg,
		teamtest.NewFakeService(),
		localcache.ProvideService(),
		tracer,
		quotatest.New(false, nil),
		supportbundlestest.NewFakeBundleService(),
		&directRestConfigProvider{host: server.URL},
	)
	require.NoError(t, err)

	legacySvc, err := userimpl.NewLegacyService(
		legacysql.NewDatabaseProvider(sqlStore),
		orgService,
		cfg,
		teamtest.NewFakeService(),
		localcache.ProvideService(),
		tracer,
		quotatest.New(false, nil),
		supportbundlestest.NewFakeBundleService(),
	)
	require.NoError(t, err)

	h.users = userSvc
	h.legacy = legacySvc
	h.password = clients.ProvideGrafana(cfg, userSvc, tracer)
	h.store = iamuser.NewLegacyStore(
		legacy.NewLegacySQLStores(legacysql.NewDatabaseProvider(sqlStore)),
		nil,
		noop.NewTracerProvider().Tracer("iam-user-test"),
	)
	h.hs = &HTTPServer{
		Cfg:                 cfg,
		userService:         userSvc,
		authInfoService:     &authinfotest.FakeService{ExpectedError: user.ErrUserNotFound},
		NotificationService: &notifications.NotificationService{Cfg: cfg},
		loginAttemptService: loginattempttest.FakeLoginAttemptService{},
		AuthTokenService:    authtest.NewFakeUserAuthTokenService(),
	}
	return h
}

func (h *passwordRedirectHarness) createAccount(t *testing.T, login string) *user.User {
	t.Helper()
	// Existing accounts are stored by the legacy user service. Password login
	// reads that row, including when later writes go to the Kubernetes service.
	created, err := h.legacy.Create(context.Background(), &user.CreateUserCommand{
		Login:    login,
		Email:    login + "@example.com",
		Name:     login,
		Password: originalLoginPassword,
		OrgID:    1,
	})
	require.NoError(t, err)
	require.NotZero(t, created.ID)
	require.NotEmpty(t, created.UID)
	require.NoError(t, h.sql.WithDbSession(context.Background(), func(sess *db.Session) error {
		now := time.Now()
		_, err := sess.Insert(&org.OrgUser{
			OrgID:   1,
			UserID:  created.ID,
			Role:    org.RoleAdmin,
			Created: now,
			Updated: now,
		})
		return err
	}))
	h.accounts[created.ID] = created
	return created
}

func (h *passwordRedirectHarness) changePassword(t *testing.T, account *user.User, oldPassword, newPassword string) *responseBody {
	t.Helper()
	body := mustJSON(t, user.ChangeUserPasswordCommand{
		OldPassword: user.Password(oldPassword),
		NewPassword: user.Password(newPassword),
	})
	reqCtx := newSignedInContext(http.MethodPut, "/api/user/password", body, &user.SignedInUser{
		UserID: account.ID,
		OrgID:  1,
		Login:  account.Login,
		Email:  account.Email,
	}, nil)
	return responseFrom(h.hs.ChangeUserPassword(reqCtx))
}

func (h *passwordRedirectHarness) resetPassword(t *testing.T, account *user.User, newPassword string) *responseBody {
	t.Helper()
	code, err := resetCodeMatchingNotifications(h.cfg, account)
	require.NoError(t, err)
	body := mustJSON(t, dtos.ResetUserPasswordForm{
		Code:            code,
		NewPassword:     user.Password(newPassword),
		ConfirmPassword: user.Password(newPassword),
	})
	reqCtx := newSignedInContext(http.MethodPost, "/api/user/password/reset", body, nil, nil)
	return responseFrom(h.hs.ResetPassword(reqCtx))
}

func (h *passwordRedirectHarness) adminUpdatePassword(t *testing.T, account *user.User, newPassword string) *responseBody {
	t.Helper()
	body := mustJSON(t, dtos.AdminUpdateUserPasswordForm{Password: user.Password(newPassword)})
	reqCtx := newSignedInContext(http.MethodPut, "/api/admin/users/"+strconv.FormatInt(account.ID, 10)+"/password", body, &user.SignedInUser{
		UserID:         account.ID + 1000,
		OrgID:          1,
		Login:          "server-admin",
		IsGrafanaAdmin: true,
	}, map[string]string{":id": strconv.FormatInt(account.ID, 10)})
	return responseFrom(h.hs.AdminUpdateUserPassword(reqCtx))
}

func (h *passwordRedirectHarness) requireLogin(t *testing.T, login, accepted, rejected string) {
	t.Helper()
	_, err := h.password.AuthenticatePassword(context.Background(), &authn.Request{}, login, accepted)
	require.NoError(t, err)
	_, err = h.password.AuthenticatePassword(context.Background(), &authn.Request{}, login, rejected)
	require.Error(t, err)
}

// serveUserResource is the app-platform user API in front of the real legacy
// user store. Listing returns the SQL user. Updates run LegacyStore.Update,
// which persists the user resource and does not receive a password field.
func (h *passwordRedirectHarness) serveUserResource(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		selector := r.URL.Query().Get("labelSelector")
		items := make([]iamv0.User, 0, 1)
		for _, account := range h.accounts {
			if selector != "" && selector != utils.LabelKeyDeprecatedInternalID+"="+strconv.FormatInt(account.ID, 10) {
				continue
			}
			items = append(items, k8sUserFromAccount(account))
		}
		if err := json.NewEncoder(w).Encode(map[string]any{
			"apiVersion": "v1",
			"kind":       "List",
			"items":      items,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	var sent iamv0.User
	if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := k8srequest.WithNamespace(r.Context(), "default")
	updated, _, err := h.store.Update(ctx, sent.Name, staticUpdatedObject{obj: &sent}, nil, nil, false, &metav1.UpdateOptions{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(updated); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func k8sUserFromAccount(account *user.User) iamv0.User {
	return iamv0.User{
		TypeMeta: metav1.TypeMeta{
			APIVersion: iamv0.GroupVersion.Identifier(),
			Kind:       "User",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            account.UID,
			Namespace:       "default",
			ResourceVersion: "1",
			Labels: map[string]string{
				utils.LabelKeyDeprecatedInternalID: strconv.FormatInt(account.ID, 10),
			},
		},
		Spec: iamv0.UserSpec{
			Login: account.Login,
			Email: account.Email,
			Title: account.Name,
			Role:  string(org.RoleAdmin),
		},
	}
}

type staticUpdatedObject struct {
	obj runtime.Object
}

func (s staticUpdatedObject) Preconditions() *metav1.Preconditions { return nil }

func (s staticUpdatedObject) UpdatedObject(context.Context, runtime.Object) (runtime.Object, error) {
	return s.obj, nil
}

var _ rest.UpdatedObjectInfo = staticUpdatedObject{}

type directRestConfigProvider struct {
	host string
}

func (p *directRestConfigProvider) GetDirectRestConfig(*contextmodel.ReqContext) *clientrest.Config {
	return &clientrest.Config{Host: p.host}
}

func (p *directRestConfigProvider) DirectlyServeHTTP(http.ResponseWriter, *http.Request) {}

func (p *directRestConfigProvider) IsReady() bool { return true }

var _ apiserver.DirectRestConfigProvider = (*directRestConfigProvider)(nil)

type responseBody struct {
	status int
	body   []byte
}

func responseFrom(resp interface {
	Status() int
	Body() []byte
}) *responseBody {
	return &responseBody{status: resp.Status(), body: resp.Body()}
}

func (r *responseBody) Status() int { return r.status }

func (r *responseBody) Body() []byte { return r.body }

func requireSuccess(t *testing.T, resp *responseBody, message string) {
	t.Helper()
	require.Equal(t, http.StatusOK, resp.Status(), string(resp.Body()))
	var payload map[string]any
	require.NoError(t, json.Unmarshal(resp.Body(), &payload))
	require.Equal(t, message, payload["message"])
}

func newSignedInContext(method, target string, body []byte, signedIn *user.SignedInUser, params map[string]string) *contextmodel.ReqContext {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if params != nil {
		req = web.SetURLParams(req, params)
	}
	reqCtx := &contextmodel.ReqContext{
		SignedInUser: signedIn,
		IsSignedIn:   signedIn != nil && signedIn.UserID > 0,
		Logger:       log.NewNopLogger(),
	}
	ctx := ctxkey.Set(req.Context(), reqCtx)
	if signedIn != nil {
		ctx = identity.WithRequester(ctx, signedIn)
	}
	req = req.WithContext(ctx)
	reqCtx.Context = &web.Context{Req: req}
	return reqCtx
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return raw
}

func enableKubernetesUsersRedirect(t *testing.T) {
	t.Helper()
	flag, err := setting.ParseFlag(featuremgmt.FlagKubernetesUsersRedirect, "true")
	require.NoError(t, err)
	provider, err := featuremgmt.CreateStaticProviderWithStandardFlags(map[string]memprovider.InMemoryFlag{
		featuremgmt.FlagKubernetesUsersRedirect: flag,
	})
	require.NoError(t, err)
	require.NoError(t, openfeature.SetProviderAndWait(provider))
	t.Cleanup(func() {
		_ = openfeature.SetProviderAndWait(memprovider.NewInMemoryProvider(nil))
	})
}

func disableKubernetesUsersRedirect(t *testing.T) {
	t.Helper()
	require.NoError(t, openfeature.SetProviderAndWait(memprovider.NewInMemoryProvider(nil)))
	t.Cleanup(func() {
		_ = openfeature.SetProviderAndWait(memprovider.NewInMemoryProvider(nil))
	})
}

// resetCodeMatchingNotifications builds the same code notifications.createUserEmailCode
// builds, so NotificationService.ValidateResetPasswordCode accepts it.
func resetCodeMatchingNotifications(cfg *setting.Cfg, account *user.User) (string, error) {
	payload := strconv.FormatInt(account.ID, 10) + account.Email + account.Login + string(account.Password) + account.Rands
	code, err := timeLimitCode(cfg.SecretKey, payload, cfg.EmailCodeValidMinutes)
	if err != nil {
		return "", err
	}
	return code + hex.EncodeToString([]byte(account.Login)), nil
}

func timeLimitCode(secretKey, payload string, minutes int) (string, error) {
	const format = "200601021504"
	start := time.Now()
	startStr := start.Format(format)
	endStr := start.Add(time.Minute * time.Duration(minutes)).Format(format)
	mac := hmac.New(sha256.New, []byte(secretKey))
	if _, err := mac.Write([]byte(payload + startStr + endStr)); err != nil {
		return "", fmt.Errorf("cannot create hmac: %w", err)
	}
	return fmt.Sprintf("%s%06d%s", startStr, minutes, hex.EncodeToString(mac.Sum(nil))), nil
}
