package interceptors_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	grpcauth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gopkg.in/ini.v1"

	"github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/components/satokengen"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	accesscontrolmock "github.com/grafana/grafana/pkg/services/accesscontrol/mock"
	"github.com/grafana/grafana/pkg/services/apikey"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl/sync"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	grpccontext "github.com/grafana/grafana/pkg/services/grpcserver/context"
	"github.com/grafana/grafana/pkg/services/grpcserver/interceptors"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

const placeholderBearer = "placeholder-bearer"

var errDatabaseUnavailable = errors.New("database unavailable")

func TestTokenAuth_FailureWarningOmitsBearer(t *testing.T) {
	const (
		orgID            = int64(1)
		serviceAccountID = int64(42)
	)

	editor := signedInAccount(serviceAccountID, orgID, org.RoleEditor, false)
	disabledAdmin := signedInAccount(serviceAccountID, orgID, org.RoleAdmin, true)
	disabledEditor := signedInAccount(serviceAccountID, orgID, org.RoleEditor, true)
	admin := signedInAccount(serviceAccountID, orgID, org.RoleAdmin, false)

	tests := []struct {
		name        string
		invoke      func(t *testing.T, authenticator interceptors.Authenticator, ctx context.Context) error
		bearer      string
		generated   bool
		key         *apikey.APIKey
		keyFailures int
		users       []signedInResult
		httpResult  httpResult
	}{
		{
			name:      "unary interceptor rejects a non-admin service account and the token still authenticates over HTTP",
			invoke:    invokeUnary,
			generated: true,
			key:       serviceAccountKey(orgID, serviceAccountID),
			users:     []signedInResult{{user: editor}},
			httpResult: httpResult{
				ok:     true,
				role:   org.RoleEditor,
				userID: serviceAccountID,
			},
		},
		{
			name:      "stream interceptor rejects a non-admin service account and the token still authenticates over HTTP",
			invoke:    invokeStream,
			generated: true,
			key:       serviceAccountKey(orgID, serviceAccountID),
			users:     []signedInResult{{user: editor}},
			httpResult: httpResult{
				ok:     true,
				role:   org.RoleEditor,
				userID: serviceAccountID,
			},
		},
		{
			name:      "per-service auth override rejects a non-admin service account and the token still authenticates over HTTP",
			invoke:    invokeServiceAuth,
			generated: true,
			key:       serviceAccountKey(orgID, serviceAccountID),
			users:     []signedInResult{{user: editor}},
			httpResult: httpResult{
				ok:     true,
				role:   org.RoleEditor,
				userID: serviceAccountID,
			},
		},
		{
			name:      "disabled admin is rejected and the bearer is not a working HTTP credential",
			invoke:    invokeUnary,
			generated: true,
			key:       serviceAccountKey(orgID, serviceAccountID),
			users:     []signedInResult{{user: disabledAdmin}},
			httpResult: httpResult{
				disabled: true,
				userID:   serviceAccountID,
			},
		},
		{
			name:      "disabled non-admin is rejected and the bearer is not a working HTTP credential",
			invoke:    invokeUnary,
			generated: true,
			key:       serviceAccountKey(orgID, serviceAccountID),
			users:     []signedInResult{{user: disabledEditor}},
			httpResult: httpResult{
				disabled: true,
				userID:   serviceAccountID,
			},
		},
		{
			name:      "user lookup error still leaves a working admin credential for HTTP",
			invoke:    invokeUnary,
			generated: true,
			key:       serviceAccountKey(orgID, serviceAccountID),
			users:     []signedInResult{{err: errDatabaseUnavailable}, {user: admin}},
			httpResult: httpResult{
				ok:     true,
				role:   org.RoleAdmin,
				userID: serviceAccountID,
			},
		},
		{
			name:        "api key lookup error still leaves a working admin credential for HTTP",
			invoke:      invokeUnary,
			generated:   true,
			key:         serviceAccountKey(orgID, serviceAccountID),
			keyFailures: 1,
			users:       []signedInResult{{user: admin}},
			httpResult: httpResult{
				ok:     true,
				role:   org.RoleAdmin,
				userID: serviceAccountID,
			},
		},
		{
			name:       "missing service account on the key is rejected over HTTP as well",
			invoke:     invokeUnary,
			generated:  true,
			key:        &apikey.APIKey{ID: 1, OrgID: orgID},
			httpResult: httpResult{rejected: true},
		},
		{
			name:       "nil api key is not a working HTTP credential",
			invoke:     invokeUnary,
			generated:  true,
			httpResult: httpResult{skip: true},
		},
		{
			name:       "nil signed-in user is rejected",
			invoke:     invokeUnary,
			generated:  true,
			key:        serviceAccountKey(orgID, serviceAccountID),
			users:      []signedInResult{{}},
			httpResult: httpResult{skip: true},
		},
		{
			name:       "user not found is rejected over HTTP as well",
			invoke:     invokeUnary,
			generated:  true,
			key:        serviceAccountKey(orgID, serviceAccountID),
			users:      []signedInResult{{err: user.ErrUserNotFound}},
			httpResult: httpResult{rejected: true, userID: serviceAccountID},
		},
		{
			name:       "malformed bearer is rejected over HTTP as well",
			invoke:     invokeUnary,
			bearer:     placeholderBearer,
			httpResult: httpResult{rejected: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logPath := captureWarningLog(t)
			bearer := tt.bearer
			var hashed string
			if tt.generated {
				generated, err := satokengen.New("sa")
				require.NoError(t, err)
				bearer = generated.ClientSecret
				hashed = generated.HashedKey
			}

			keys := &boundAPIKeyService{hash: hashed, key: tt.key, failRemaining: tt.keyFailures, err: errDatabaseUnavailable}
			users := &scriptedUserService{wantUserID: serviceAccountID, wantOrgID: orgID, results: tt.users}
			authenticator := interceptors.ProvideAuthenticator(keys, users, accesscontrolmock.New(), grpccontext.ProvideContextHandler(tracing.InitializeTracerForTest()))

			err := tt.invoke(t, authenticator, incomingBearer(bearer))
			require.Error(t, err)
			require.Equal(t, codes.Unauthenticated, status.Code(err))
			require.Equal(t, "invalid token", status.Convert(err).Message())

			written, readErr := os.ReadFile(logPath)
			require.NoError(t, readErr)
			assertWarningOmitsBearer(t, string(written), bearer)

			if tt.httpResult.skip {
				return
			}
			identity, httpErr := authenticateHTTP(t, keys, users, bearer)
			assertHTTPResult(t, tt.httpResult, identity, httpErr)
		})
	}
}

type httpResult struct {
	ok       bool
	disabled bool
	rejected bool
	skip     bool
	role     org.RoleType
	userID   int64
}

type signedInResult struct {
	user *user.SignedInUser
	err  error
}

func invokeUnary(t *testing.T, authenticator interceptors.Authenticator, ctx context.Context) error {
	t.Helper()
	_, err := grpcauth.UnaryServerInterceptor(authenticator.Authenticate)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Call"}, func(context.Context, any) (any, error) {
		t.Fatal("unary handler ran after authentication failed")
		return nil, nil
	})
	return err
}

func invokeStream(t *testing.T, authenticator interceptors.Authenticator, ctx context.Context) error {
	t.Helper()
	return grpcauth.StreamServerInterceptor(authenticator.Authenticate)(nil, contextStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: "/test.Service/Watch"}, func(any, grpc.ServerStream) error {
		t.Fatal("stream handler ran after authentication failed")
		return nil
	})
}

func invokeServiceAuth(t *testing.T, authenticator interceptors.Authenticator, ctx context.Context) error {
	t.Helper()
	_, err := interceptors.NewServiceAuth(authenticator).AuthFuncOverride(ctx, "/resource.ResourceStore/List")
	return err
}

type contextStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s contextStream) Context() context.Context { return s.ctx }

func incomingBearer(bearer string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+bearer))
}

func serviceAccountKey(orgID, serviceAccountID int64) *apikey.APIKey {
	id := serviceAccountID
	return &apikey.APIKey{ID: 1, OrgID: orgID, ServiceAccountId: &id}
}

func signedInAccount(id, orgID int64, role org.RoleType, disabled bool) *user.SignedInUser {
	return &user.SignedInUser{
		UserID:           id,
		OrgID:            orgID,
		OrgRole:          role,
		IsDisabled:       disabled,
		IsServiceAccount: true,
	}
}

type boundAPIKeyService struct {
	apikey.Service
	hash          string
	key           *apikey.APIKey
	failRemaining int
	err           error
}

func (s *boundAPIKeyService) GetAPIKeyByHash(_ context.Context, hash string) (*apikey.APIKey, error) {
	if hash != s.hash {
		return nil, apikey.ErrNotFound
	}
	if s.failRemaining > 0 {
		s.failRemaining--
		return nil, s.err
	}
	return s.key, nil
}

func (s *boundAPIKeyService) UpdateAPIKeyLastUsedDate(context.Context, int64) error {
	return nil
}

type scriptedUserService struct {
	user.Service
	wantUserID int64
	wantOrgID  int64
	results    []signedInResult
	index      int
}

func (s *scriptedUserService) GetSignedInUser(_ context.Context, query *user.GetSignedInUserQuery) (*user.SignedInUser, error) {
	if query.UserID != s.wantUserID || query.OrgID != s.wantOrgID {
		return nil, errors.New("user lookup id does not match the service account")
	}
	if len(s.results) == 0 {
		return nil, errors.New("no scripted user result")
	}
	result := s.results[s.index]
	if s.index < len(s.results)-1 {
		s.index++
	}
	return result.user, result.err
}

func authenticateHTTP(t *testing.T, keys apikey.Service, users user.Service, bearer string) (*authn.Identity, error) {
	t.Helper()
	cfg := setting.NewCfg()
	tracer := tracing.InitializeTracerForTest()
	svc := authnimpl.ProvideService(cfg, tracer, nil, &usagestats.NoopUsageStats{}, nil, nil)
	svc.RegisterClient(clients.ProvideAPIKey(keys, tracer))
	userSync := sync.ProvideUserSync(users, nil, nil, nil, tracer, featuremgmt.WithFeatures(), cfg, nil)
	svc.RegisterPostAuthHook(userSync.FetchSyncedUserHook, 100)
	permissions := accesscontrolmock.New().WithPermissions([]accesscontrol.Permission{{
		Action: accesscontrol.ActionUsersWrite,
		Scope:  accesscontrol.ScopeUsersAll,
	}})
	svc.RegisterPostAuthHook(sync.ProvideRBACSync(cfg, permissions, tracer, nil).SyncPermissionsHook, 120)

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/api/org", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+bearer)
	return svc.Authenticate(context.Background(), &authn.Request{HTTPRequest: req})
}

func assertHTTPResult(t *testing.T, want httpResult, identity *authn.Identity, err error) {
	t.Helper()
	switch {
	case want.ok:
		require.NoError(t, err)
		require.NotNil(t, identity)
		require.Equal(t, types.TypeServiceAccount, identity.Type)
		require.Equal(t, want.userID, mustInternalID(t, identity))
		require.Equal(t, want.role, identity.OrgRoles[identity.OrgID])
		require.Equal(t, []string{accesscontrol.ScopeUsersAll}, identity.Permissions[identity.OrgID][accesscontrol.ActionUsersWrite])
		require.False(t, identity.IsDisabled)
	case want.disabled:
		require.Error(t, err)
		require.Nil(t, identity)
		require.Contains(t, err.Error(), "identity is disabled")
	case want.rejected:
		require.Error(t, err)
		require.Nil(t, identity)
	default:
		t.Fatalf("http result is not specified")
	}
}

func mustInternalID(t *testing.T, identity *authn.Identity) int64 {
	t.Helper()
	id, err := identity.GetInternalID()
	require.NoError(t, err)
	return id
}

func assertWarningOmitsBearer(t *testing.T, logText, bearer string) {
	t.Helper()
	if !strings.Contains(logText, "level=warn") || !strings.Contains(logText, "request with invalid token") {
		t.Errorf("authentication failure was not written to the warning log (%d bytes)", len(logText))
	}
	if bearer != "" && strings.Contains(logText, bearer) {
		t.Errorf("warning log contains the bearer token")
	}
	decoded, err := satokengen.Decode(bearer)
	if err == nil && decoded.Secret != "" && strings.Contains(logText, decoded.Secret) {
		t.Errorf("warning log contains the bearer secret")
	}
}

func captureWarningLog(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "grafana.log")
	file := ini.Empty()
	section, err := file.NewSection("log")
	require.NoError(t, err)
	_, err = section.NewKey("level", "info")
	require.NoError(t, err)
	fileSection, err := file.NewSection("log.file")
	require.NoError(t, err)
	_, err = fileSection.NewKey("level", "info")
	require.NoError(t, err)
	_, err = fileSection.NewKey("format", "text")
	require.NoError(t, err)
	_, err = fileSection.NewKey("file_name", path)
	require.NoError(t, err)
	_, err = fileSection.NewKey("log_rotate", "false")
	require.NoError(t, err)
	_, err = fileSection.NewKey("daily_rotate", "false")
	require.NoError(t, err)
	require.NoError(t, log.ReadLoggingConfig([]string{"file"}, "", file))
	t.Cleanup(func() {
		restore := ini.Empty()
		consoleLog, consoleErr := restore.NewSection("log")
		if consoleErr != nil {
			return
		}
		_, _ = consoleLog.NewKey("level", "error")
		console, consoleErr := restore.NewSection("log.console")
		if consoleErr != nil {
			return
		}
		_, _ = console.NewKey("level", "error")
		_, _ = console.NewKey("format", "text")
		_ = log.ReadLoggingConfig([]string{"console"}, "", restore)
	})
	return path
}
