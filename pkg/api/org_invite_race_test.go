package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/searchusers"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	tempuser "github.com/grafana/grafana/pkg/services/temp_user"
	"github.com/grafana/grafana/pkg/services/temp_user/tempuserimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/web"
)

// pendingReadGate pauses the first completion that has observed a still-pending
// invite until another completion has observed that same pending row. The wait
// starts only after that read's database session has been released.
//
// Re-reading the status before creating the user does not satisfy this test:
// both requests are released while the row is still pending, and both continue
// into account creation. Claiming the row in the database before creating a
// user does, because the second read no longer observes a pending invite.
type pendingReadGate struct {
	code    string
	mu      sync.Mutex
	arrived int
	release chan struct{}
	once    sync.Once
}

func newPendingReadGate(code string) *pendingReadGate {
	return &pendingReadGate{code: code, release: make(chan struct{})}
}

func (g *pendingReadGate) afterPendingRead(code string, status tempuser.TempUserStatus) {
	if g == nil || code != g.code || status != tempuser.TmpUserInvitePending {
		return
	}
	g.mu.Lock()
	g.arrived++
	n := g.arrived
	g.mu.Unlock()
	if n == 1 {
		select {
		case <-g.release:
		case <-time.After(2 * time.Second):
		}
		return
	}
	g.once.Do(func() { close(g.release) })
}

// gatingTempUserService is the real temp-user service. It only delays the two
// completions so their pending reads overlap. Every read and write still goes
// to the database.
type gatingTempUserService struct {
	tempuser.Service
	gate *pendingReadGate
}

func (s *gatingTempUserService) GetTempUserByCode(ctx context.Context, query *tempuser.GetTempUserByCodeQuery) (*tempuser.TempUserDTO, error) {
	res, err := s.Service.GetTempUserByCode(ctx, query)
	if err != nil || res == nil {
		return res, err
	}
	s.gate.afterPendingRead(res.Code, res.Status)
	return res, nil
}

func TestOrgInviteReuse(t *testing.T) {
	const (
		inviteCode = "invite-code-under-test"
		loginName  = "invited-person"
		emailOne   = "a.one@example.com"
		emailTwo   = "b.two@example.com"
		userOne    = "a-one"
		userTwo    = "b-two"
	)

	t.Run("concurrent completions of one username invite create one admin", func(t *testing.T) {
		env := newInviteCompletionEnv(t, &pendingReadGateSetup{code: inviteCode})
		orgID := env.createOrgWithPendingInvite(t, inviteCode, loginName, org.RoleAdmin)

		results := env.completeConcurrently(t, []inviteCompletion{
			{email: emailOne, username: userOne},
			{email: emailTwo, username: userTwo},
		}, inviteCode)

		created := env.inviteesInOrg(t, orgID, emailOne, emailTwo)
		require.Lenf(t, created, 1,
			"one pending invite whose login is not an email must add one organization admin when two unauthenticated completions run together; responses: %s; accounts in org: %+v",
			formatCompletionResults(results), created)
		require.Equal(t, org.RoleAdmin, created[0].role)
	})

	t.Run("a second completion after the first finishes creates no account", func(t *testing.T) {
		env := newInviteCompletionEnv(t, nil)
		orgID := env.createOrgWithPendingInvite(t, inviteCode, loginName, org.RoleAdmin)

		first, err := env.complete(inviteCompletion{email: emailOne, username: userOne}, inviteCode)
		require.NoError(t, err)
		require.Equalf(t, http.StatusOK, first.status, "first completion body: %s", first.body)

		second, err := env.complete(inviteCompletion{email: emailTwo, username: userTwo}, inviteCode)
		require.NoError(t, err)
		require.NotEqualf(t, http.StatusOK, second.status, "second completion body: %s", second.body)

		created := env.inviteesInOrg(t, orgID, emailOne, emailTwo)
		require.Len(t, created, 1)
		require.Equal(t, emailOne, created[0].email)
		require.Equal(t, org.RoleAdmin, created[0].role)
	})
}

type pendingReadGateSetup struct {
	code string
}

type inviteCompletion struct {
	email    string
	username string
}

type completionResult struct {
	email  string
	status int
	body   string
}

func formatCompletionResults(results []completionResult) string {
	parts := make([]string, 0, len(results))
	for _, result := range results {
		parts = append(parts, fmt.Sprintf("%s status=%d body=%s", result.email, result.status, result.body))
	}
	return strings.Join(parts, "; ")
}

type orgInvitee struct {
	email  string
	userID int64
	role   org.RoleType
}

type inviteCompletionEnv struct {
	cfg      *setting.Cfg
	server   *httptest.Server
	client   *http.Client
	userSvc  user.Service
	orgSvc   org.Service
	tempUser tempuser.Service
}

func newInviteCompletionEnv(t *testing.T, gateSetup *pendingReadGateSetup) *inviteCompletionEnv {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.AutoAssignOrg = false
	// Production default from pkg/setting/setting_authn.go. CSRF skips requests that do not send this cookie.
	cfg.LoginCookieName = "grafana_session"

	sqlStore := db.NewTestStore(t, db.WithCfg(cfg))
	tracer := tracing.InitializeTracerForTest()
	quotaSvc := quotatest.New(false, nil)
	orgSvc, err := orgimpl.ProvideService(legacysql.NewDatabaseProvider(sqlStore), cfg, quotaSvc)
	require.NoError(t, err)
	userSvc, err := userimpl.ProvideService(
		legacysql.NewDatabaseProvider(sqlStore), orgSvc, cfg, nil, nil, tracer,
		quotaSvc, supportbundlestest.NewFakeBundleService(), nil,
	)
	require.NoError(t, err)

	var tempUserSvc tempuser.Service = tempuserimpl.ProvideService(sqlStore, cfg)
	if gateSetup != nil {
		tempUserSvc = &gatingTempUserService{
			Service: tempUserSvc,
			gate:    newPendingReadGate(gateSetup.code),
		}
	}

	hs := &HTTPServer{
		RouteRegister:      routing.NewRouteRegister(),
		Cfg:                cfg,
		Features:           featuremgmt.WithFeatures(),
		License:            &licensing.OSSLicensingService{},
		QuotaService:       quotaSvc,
		AccessControl:      acimpl.ProvideAccessControl(featuremgmt.WithFeatures()),
		searchUsersService: &searchusers.OSSService{},
		log:                log.New("invite-reuse-test"),
		bus:                bus.ProvideBus(tracer),
		tracer:             tracer,
		SQLStore:           sqlStore,
		userService:        userSvc,
		orgService:         orgSvc,
		tempUserService:    tempUserSvc,
		AuthTokenService:   authtest.NewFakeUserAuthTokenService(),
		ContextHandler: contexthandler.ProvideService(cfg, &authntest.FakeService{
			ExpectedErr: errors.New("no credentials"),
		}, featuremgmt.WithFeatures()),
		Csrf: csrf.ProvideCSRFFilter(cfg),
	}
	hs.registerRoutes()

	m := web.New()
	m.UseMiddleware(hs.Csrf.Middleware())
	m.UseMiddleware(hs.ContextHandler.Middleware)
	m.Use(middleware.OrgRedirect(cfg, userSvc))
	hs.RouteRegister.Register(m.Router)

	httpServer := httptest.NewServer(m)
	t.Cleanup(httpServer.Close)

	return &inviteCompletionEnv{
		cfg:      cfg,
		server:   httpServer,
		client:   &http.Client{Timeout: 30 * time.Second},
		userSvc:  userSvc,
		orgSvc:   orgSvc,
		tempUser: tempUserSvc,
	}
}

func (e *inviteCompletionEnv) createOrgWithPendingInvite(t *testing.T, code, login string, role org.RoleType) int64 {
	t.Helper()
	ctx := context.Background()

	inviter, err := e.userSvc.Create(ctx, &user.CreateUserCommand{
		Email:    "inviter@example.com",
		Login:    "inviter",
		Name:     "Inviter",
		Password: "placeholder-password",
		OrgName:  "Invited Org",
	})
	require.NoError(t, err)
	require.NotZero(t, inviter.OrgID)

	_, err = e.tempUser.CreateTempUser(ctx, &tempuser.CreateTempUserCommand{
		OrgID:           inviter.OrgID,
		Email:           login,
		Name:            "Invited Person",
		Status:          tempuser.TmpUserInvitePending,
		Code:            code,
		Role:            role,
		InvitedByUserID: inviter.ID,
	})
	require.NoError(t, err)
	return inviter.OrgID
}

func (e *inviteCompletionEnv) completeConcurrently(t *testing.T, completions []inviteCompletion, code string) []completionResult {
	t.Helper()

	start := make(chan struct{})
	results := make([]completionResult, len(completions))
	errs := make([]error, len(completions))
	var wg sync.WaitGroup
	for i, completion := range completions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i], errs[i] = e.complete(completion, code)
		}()
	}
	close(start)
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	return results
}

func (e *inviteCompletionEnv) complete(completion inviteCompletion, code string) (completionResult, error) {
	body := fmt.Sprintf(
		`{"inviteCode":%q,"email":%q,"name":"Invited","username":%q,"password":"placeholder-password"}`,
		code, completion.email, completion.username,
	)
	req, err := http.NewRequest(http.MethodPost, e.server.URL+"/api/user/invite/complete", strings.NewReader(body))
	if err != nil {
		return completionResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return completionResult{}, err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return completionResult{}, err
	}

	return completionResult{email: completion.email, status: resp.StatusCode, body: string(payload)}, nil
}

func (e *inviteCompletionEnv) inviteesInOrg(t *testing.T, orgID int64, emails ...string) []orgInvitee {
	t.Helper()
	ctx := context.Background()

	var created []orgInvitee
	for _, email := range emails {
		usr, err := e.userSvc.GetByEmail(ctx, &user.GetUserByEmailQuery{Email: email})
		if errors.Is(err, user.ErrUserNotFound) {
			continue
		}
		require.NoError(t, err)

		memberships, err := e.orgSvc.GetUserOrgList(ctx, &org.GetUserOrgListQuery{UserID: usr.ID})
		require.NoError(t, err)
		for _, membership := range memberships {
			if membership.OrgID != orgID {
				continue
			}
			created = append(created, orgInvitee{email: email, userID: usr.ID, role: membership.Role})
		}
	}
	return created
}
