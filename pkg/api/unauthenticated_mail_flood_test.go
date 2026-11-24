package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/services/login/authinfotest"
	"github.com/grafana/grafana/pkg/services/notifications"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/searchusers"
	"github.com/grafana/grafana/pkg/services/temp_user/tempusertest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// Budgets the unauthenticated mail endpoints must enforce. A burst is a
// sequence of requests with no delay. Repeats for one account, including a
// different client address and a different spelling of the same login or
// email, still count as that account.
const (
	resetEmailsPerAccount        = 1
	unauthenticatedMailPerClient = 3
)

// TestUnauthenticatedResetPasswordEmailIsLimited posts to the registered
// password-reset route with no session cookie. SMTP is enabled, which is the
// configuration the reset form needs in order to send mail.
func TestUnauthenticatedResetPasswordEmailIsLimited(t *testing.T) {
	t.Run("one account", func(t *testing.T) {
		active := &user.User{ID: 7, Login: "victim", Email: "victim@example.com", Name: "Victim"}
		disabled := &user.User{ID: 8, Login: "disabled", Email: "disabled@example.com", Name: "Disabled", IsDisabled: true}
		env := newMailFloodEnv(t, active, disabled)
		clientIP := "203.0.113.10"
		otherIP := "203.0.113.20"

		identifiers := []string{
			"victim",
			"Victim",
			"victim@example.com",
			"VICTIM@example.com",
			"victim",
			"victim@example.com",
		}
		for _, id := range identifiers {
			env.postReset(t, clientIP, id)
		}
		for range 2 {
			env.postReset(t, otherIP, "victim")
		}
		env.postReset(t, clientIP, "disabled")
		env.postReset(t, clientIP, "nobody@example.com")

		msgs := env.delivered(t)
		require.Equalf(t, resetEmailsPerAccount, len(msgs), "recipients: %v", recipients(msgs))
		require.Equal(t, []string{"victim@example.com"}, msgs[0].to)
		require.True(t, strings.Contains(msgs[0].data, "user/password/reset?code="))
	})

	t.Run("one client address across accounts", func(t *testing.T) {
		users := make([]*user.User, 0, 7)
		for i := 1; i <= 7; i++ {
			login := "user" + string(rune('0'+i))
			users = append(users, &user.User{
				ID:    int64(i),
				Login: login,
				Email: login + "@example.com",
				Name:  "User",
			})
		}
		env := newMailFloodEnv(t, users...)
		clientIP := "203.0.113.30"
		otherIP := "203.0.113.40"
		for _, usr := range users[:6] {
			env.postReset(t, clientIP, usr.Login)
		}
		env.postReset(t, otherIP, users[6].Login)

		msgs := env.delivered(t)
		perUser := map[string]int{}
		for _, msg := range msgs {
			require.Len(t, msg.to, 1)
			perUser[msg.to[0]]++
			require.True(t, strings.Contains(msg.data, "user/password/reset?code="))
		}
		fromClient := 0
		for _, usr := range users[:6] {
			fromClient += perUser[usr.Email]
			require.LessOrEqual(t, perUser[usr.Email], resetEmailsPerAccount)
		}
		require.Equal(t, unauthenticatedMailPerClient, fromClient)
		require.Equal(t, resetEmailsPerAccount, perUser[users[6].Email])
	})
}

// TestUnauthenticatedSignupEmailIsLimited covers the other anonymous routes
// that queue mail for an address the caller chooses: signup verification and
// the welcome message sent when signup completes.
func TestUnauthenticatedSignupEmailIsLimited(t *testing.T) {
	t.Run("verification", func(t *testing.T) {
		env := newMailFloodEnv(t)
		env.cfg.AllowUserSignUp = true
		env.cfg.VerifyEmailEnabled = true
		assertClientMailBudget(t, env, "signup", func(ip, email string) {
			_, _ = env.postJSON(t, "/api/user/signup", ip, map[string]string{"email": email})
		}, "Complete the signup")
	})

	t.Run("welcome", func(t *testing.T) {
		env := newMailFloodEnv(t)
		env.cfg.AllowUserSignUp = true
		env.cfg.Smtp.SendWelcomeEmailOnSignUp = true
		env.users.CreateFn = func(_ context.Context, cmd *user.CreateUserCommand) (*user.User, error) {
			return &user.User{ID: 1, Email: cmd.Email, Login: cmd.Login, Name: cmd.Name}, nil
		}
		assertClientMailBudget(t, env, "welcome", func(ip, email string) {
			_, _ = env.postJSON(t, "/api/user/signup/step2", ip, map[string]any{
				"email":    email,
				"name":     "Signup",
				"username": strings.Split(email, "@")[0],
				"password": "placeholder",
			})
		}, "Welcome")
	})
}

// assertClientMailBudget sends six messages from one client address and one
// more from another. Each of the first six addresses gets at most one message
// and together they get unauthenticatedMailPerClient. The other address gets one.
func assertClientMailBudget(t *testing.T, env *mailFloodEnv, kind string, post func(ip, email string), marker string) {
	t.Helper()
	clientIP := "198.51.100.10"
	otherIP := "198.51.100.20"
	var first []string
	for i := 1; i <= 6; i++ {
		email := kind + string(rune('0'+i)) + "@example.com"
		first = append(first, email)
		post(clientIP, email)
	}
	other := kind + "7@example.com"
	post(otherIP, other)

	perUser := map[string]int{}
	for _, msg := range env.delivered(t) {
		require.Len(t, msg.to, 1)
		perUser[msg.to[0]]++
		require.True(t, strings.Contains(msg.data, marker))
	}
	fromClient := 0
	for _, email := range first {
		fromClient += perUser[email]
		require.LessOrEqual(t, perUser[email], 1)
	}
	require.Equal(t, unauthenticatedMailPerClient, fromClient)
	require.Equal(t, 1, perUser[other])
}

type smtpMessage struct {
	to   []string
	data string
}

type mailFloodEnv struct {
	cfg    *setting.Cfg
	users  *floodUserService
	server *httptest.Server
	client *http.Client
	sink   *smtpSink
}

func newMailFloodEnv(t *testing.T, users ...*user.User) *mailFloodEnv {
	t.Helper()

	sink := startSMTPSink(t)
	cfg := setting.NewCfg()
	cfg.LoginCookieName = "grafana_session"
	staticRoot, err := filepath.Abs("../../public")
	require.NoError(t, err)
	cfg.StaticRootPath = staticRoot
	cfg.Smtp.Enabled = true
	cfg.Smtp.Host = sink.addr
	cfg.Smtp.FromAddress = "from@example.com"
	cfg.Smtp.FromName = "Grafana"
	cfg.Smtp.ContentTypes = []string{"text/html"}
	cfg.Smtp.TemplatesPatterns = []string{"emails/*.html", "emails/*.txt"}

	userSvc := newFloodUserService(users)
	tempUsers := &tempusertest.FakeTempUserService{}
	mailer, err := notifications.ProvideSmtpService(cfg)
	require.NoError(t, err)
	eventBus := bus.ProvideBus(tracing.InitializeTracerForTest())
	ns, err := notifications.ProvideService(eventBus, cfg, mailer, tempUsers)
	require.NoError(t, err)
	runCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = ns.Run(runCtx)
	}()

	hs := &HTTPServer{
		log:                 log.New("mail-flood-test"),
		RouteRegister:       routing.ProvideRegister(),
		Cfg:                 cfg,
		Features:            featuremgmt.WithFeatures(),
		License:             &licensing.OSSLicensingService{},
		QuotaService:        quotatest.New(false, nil),
		searchUsersService:  &searchusers.OSSService{},
		bus:                 eventBus,
		NotificationService: ns,
		userService:         userSvc,
		tempUserService:     tempUsers,
		authInfoService:     &authinfotest.FakeService{ExpectedError: user.ErrUserNotFound},
		AuthTokenService:    authtest.NewFakeUserAuthTokenService(),
	}
	hs.registerRoutes()

	mux := web.New()
	mux.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())
	mux.Use(contexthandler.ProvideService(
		cfg,
		&authntest.FakeService{ExpectedErr: errors.New("no credentials")},
		featuremgmt.WithFeatures(),
	).Middleware)
	hs.RouteRegister.Register(mux)

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &mailFloodEnv{
		cfg:    cfg,
		users:  userSvc,
		server: server,
		client: &http.Client{Timeout: 10 * time.Second},
		sink:   sink,
	}
}

func (e *mailFloodEnv) postReset(t *testing.T, clientIP, userOrEmail string) {
	t.Helper()
	status, body := e.postJSON(t, "/api/user/password/send-reset-email", clientIP, map[string]string{
		"userOrEmail": userOrEmail,
	})
	require.Equal(t, http.StatusOK, status, body)
	require.Contains(t, body, "Email sent")
}

func (e *mailFloodEnv) postJSON(t *testing.T, path, clientIP string, payload any) (int, string) {
	t.Helper()
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, e.server.URL+path, bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", clientIP)
	resp, err := e.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

func (e *mailFloodEnv) delivered(t *testing.T) []smtpMessage {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	last := e.sink.snapshot()
	changed := time.Now()
	for time.Now().Before(deadline) {
		cur := e.sink.snapshot()
		if len(cur) != len(last) {
			last = cur
			changed = time.Now()
		}
		if len(last) > 0 && time.Since(changed) >= 500*time.Millisecond {
			return last
		}
		time.Sleep(25 * time.Millisecond)
	}
	return e.sink.snapshot()
}

// floodUserService applies the same login-or-email match as the user store:
// lowercase the input, look up by email when it contains '@', otherwise by login.
type floodUserService struct {
	*usertest.FakeUserService
	byLogin map[string]*user.User
	byEmail map[string]*user.User
}

func newFloodUserService(users []*user.User) *floodUserService {
	svc := &floodUserService{
		FakeUserService: usertest.NewUserServiceFake(),
		byLogin:         map[string]*user.User{},
		byEmail:         map[string]*user.User{},
	}
	for _, usr := range users {
		svc.byLogin[strings.ToLower(usr.Login)] = usr
		svc.byEmail[strings.ToLower(usr.Email)] = usr
	}
	return svc
}

func (s *floodUserService) GetByLogin(_ context.Context, query *user.GetUserByLoginQuery) (*user.User, error) {
	loginOrEmail := strings.ToLower(query.LoginOrEmail)
	if loginOrEmail == "" {
		return nil, user.ErrUserNotFound
	}
	if strings.Contains(loginOrEmail, "@") {
		if usr, ok := s.byEmail[loginOrEmail]; ok {
			return usr, nil
		}
	}
	if usr, ok := s.byLogin[loginOrEmail]; ok {
		return usr, nil
	}
	return nil, user.ErrUserNotFound
}

func (s *floodUserService) GetByLoginWithPassword(ctx context.Context, query *user.GetUserByLoginQuery) (*user.User, error) {
	return s.GetByLogin(ctx, query)
}

// smtpSink speaks the SMTP commands gopkg.in/mail.v2 v2.3.1's dialer sends
// through net/smtp.Client (Go 1.26.6): greeting 220, EHLO/HELO 250, MAIL 250,
// RCPT 250, DATA 354, then a dot-stuffed body and 250.
type smtpSink struct {
	addr string

	mu   sync.Mutex
	msgs []smtpMessage
}

func startSMTPSink(t *testing.T) *smtpSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	sink := &smtpSink{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go sink.serve(conn)
		}
	}()
	return sink
}

func (s *smtpSink) snapshot() []smtpMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]smtpMessage, len(s.msgs))
	copy(out, s.msgs)
	return out
}

func (s *smtpSink) serve(conn net.Conn) {
	defer conn.Close()
	tp := textproto.NewConn(conn)
	if err := tp.PrintfLine("220 localhost ESMTP"); err != nil {
		return
	}
	var rcpt []string
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO ") || strings.HasPrefix(upper, "HELO "):
			if err := tp.PrintfLine("250 localhost"); err != nil {
				return
			}
		case strings.HasPrefix(upper, "MAIL FROM:"):
			if err := tp.PrintfLine("250 OK"); err != nil {
				return
			}
		case strings.HasPrefix(upper, "RCPT TO:"):
			rcpt = append(rcpt, smtpAddr(line))
			if err := tp.PrintfLine("250 OK"); err != nil {
				return
			}
		case upper == "DATA":
			if err := tp.PrintfLine("354 End data with <CR><LF>.<CR><LF>"); err != nil {
				return
			}
			body, err := io.ReadAll(tp.DotReader())
			if err != nil {
				return
			}
			if err := tp.PrintfLine("250 OK"); err != nil {
				return
			}
			s.mu.Lock()
			s.msgs = append(s.msgs, smtpMessage{to: append([]string(nil), rcpt...), data: string(body)})
			s.mu.Unlock()
			rcpt = nil
		case upper == "RSET" || upper == "NOOP":
			rcpt = nil
			if err := tp.PrintfLine("250 OK"); err != nil {
				return
			}
		case upper == "QUIT":
			_ = tp.PrintfLine("221 Bye")
			return
		default:
			if err := tp.PrintfLine("502 command not implemented"); err != nil {
				return
			}
		}
	}
}

func recipients(msgs []smtpMessage) []string {
	out := make([]string, 0, len(msgs))
	for _, msg := range msgs {
		out = append(out, strings.Join(msg.to, ","))
	}
	return out
}

func smtpAddr(line string) string {
	_, addr, ok := strings.Cut(line, ":")
	if !ok {
		return ""
	}
	addr = strings.TrimSpace(addr)
	addr = strings.Trim(addr, "<>")
	if i := strings.IndexAny(addr, " \t"); i >= 0 {
		addr = addr[:i]
	}
	return strings.ToLower(addr)
}
