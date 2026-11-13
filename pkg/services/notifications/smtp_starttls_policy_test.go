package notifications

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gomail "gopkg.in/mail.v2"

	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/events"
	tempuser "github.com/grafana/grafana/pkg/services/temp_user"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

// smtpCredentialPlaceholder is not a real credential. It is the value the
// dialer must not write on a connection that never completed STARTTLS.
const smtpCredentialPlaceholder = "placeholder-smtp-secret"

const smtpUserPlaceholder = "smtp-user-placeholder"

const remoteSMTPHost = "mail.example.test"

// cleartextSMTP is an SMTP peer that answers EHLO without STARTTLS and
// advertises only AUTH LOGIN. gomail v2.3.1 selects its LOGIN authenticator
// for that advertisement and, unlike net/smtp PlainAuth, that authenticator
// submits the username and password on a connection that is not using TLS.
type cleartextSMTP struct {
	addr string
	ln   net.Listener

	mu       sync.Mutex
	client   []byte
	sessions int
	wake     chan struct{}
}

func startCleartextSMTP(t *testing.T) *cleartextSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &cleartextSMTP{addr: ln.Addr().String(), ln: ln, wake: make(chan struct{}, 1)}
	go srv.accept()
	t.Cleanup(func() { _ = ln.Close() })
	return srv
}

func (s *cleartextSMTP) accept() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.session(conn)
	}
}

func (s *cleartextSMTP) session(conn net.Conn) {
	defer conn.Close()
	defer s.finishSession()

	reader := bufio.NewReader(conn)
	_, _ = fmt.Fprintf(conn, "220 %s ESMTP\r\n", remoteSMTPHost)
	for {
		line, err := readSMTPLine(conn, reader)
		s.record(line)
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(strings.SplitN(strings.TrimRight(line, "\r\n"), " ", 2)[0]))
		switch cmd {
		case "EHLO", "HELO":
			// The first line is the greeting. Later lines are extensions.
			// STARTTLS is intentionally absent.
			_, _ = fmt.Fprintf(conn, "250-%s\r\n250 AUTH LOGIN\r\n", remoteSMTPHost)
		case "AUTH":
			if !s.login(conn, reader, line) {
				return
			}
		case "MAIL", "RCPT", "RSET", "NOOP":
			_, _ = fmt.Fprintf(conn, "250 OK\r\n")
		case "DATA":
			_, _ = fmt.Fprintf(conn, "354 End data with <CR><LF>.<CR><LF>\r\n")
			if !s.readData(conn, reader) {
				return
			}
			_, _ = fmt.Fprintf(conn, "250 OK\r\n")
		case "QUIT":
			_, _ = fmt.Fprintf(conn, "221 Bye\r\n")
			return
		default:
			_, _ = fmt.Fprintf(conn, "502 Command not implemented\r\n")
		}
	}
}

func (s *cleartextSMTP) login(conn net.Conn, reader *bufio.Reader, first string) bool {
	fields := strings.Fields(strings.TrimRight(first, "\r\n"))
	if len(fields) < 2 || !strings.EqualFold(fields[1], "LOGIN") {
		_, _ = fmt.Fprintf(conn, "535 Authentication failed\r\n")
		return true
	}
	if len(fields) == 2 {
		if !s.challenge(conn, reader, "Username:") {
			return false
		}
	}
	return s.challenge(conn, reader, "Password:")
}

func (s *cleartextSMTP) challenge(conn net.Conn, reader *bufio.Reader, prompt string) bool {
	_, _ = fmt.Fprintf(conn, "334 %s\r\n", base64.StdEncoding.EncodeToString([]byte(prompt)))
	line, err := readSMTPLine(conn, reader)
	s.record(line)
	if err != nil {
		return false
	}
	if strings.TrimSpace(line) == "*" {
		_, _ = fmt.Fprintf(conn, "501 AUTH aborted\r\n")
		return true
	}
	if prompt == "Password:" {
		_, _ = fmt.Fprintf(conn, "235 Authentication successful\r\n")
	}
	return true
}

func (s *cleartextSMTP) readData(conn net.Conn, reader *bufio.Reader) bool {
	for {
		line, err := readSMTPLine(conn, reader)
		s.record(line)
		if err != nil {
			return false
		}
		if strings.TrimRight(line, "\r\n") == "." {
			return true
		}
	}
}

func readSMTPLine(conn net.Conn, reader *bufio.Reader) (string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	return reader.ReadString('\n')
}

func (s *cleartextSMTP) record(line string) {
	if line == "" {
		return
	}
	s.mu.Lock()
	s.client = append(s.client, line...)
	s.mu.Unlock()
}

func (s *cleartextSMTP) finishSession() {
	s.mu.Lock()
	s.sessions++
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *cleartextSMTP) waitSessions(n int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		s.mu.Lock()
		got := s.sessions
		s.mu.Unlock()
		if got >= n || time.Now().After(deadline) {
			return got
		}
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-s.wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (s *cleartextSMTP) clientBytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.client...)
}

// redirectSMTPDial keeps the configured host for every check inside the
// dialer and only replaces the TCP destination, so this process can answer
// as the peer on that path.
func redirectSMTPDial(t *testing.T, srv *cleartextSMTP) {
	t.Helper()
	previous := gomail.NetDialTimeout
	gomail.NetDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil || !strings.EqualFold(host, remoteSMTPHost) {
			return previous(network, address, timeout)
		}
		return net.DialTimeout(network, srv.addr, timeout)
	}
	t.Cleanup(func() { gomail.NetDialTimeout = previous })
}

func loadEnabledSMTPConfig(t *testing.T, startTLSPolicy string) *setting.Cfg {
	t.Helper()
	if v := os.Getenv("GF_SMTP_STARTTLS_POLICY"); v != "" {
		t.Fatal("GF_SMTP_STARTTLS_POLICY is set and would hide the shipped default")
	}
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	require.FileExists(t, filepath.Join(root, "conf", "defaults.ini"))

	dir := t.TempDir()
	policyLine := ""
	if startTLSPolicy != "" {
		policyLine = "startTLS_policy = " + startTLSPolicy + "\n"
	}
	custom := fmt.Sprintf(`
[paths]
data = %s
logs = %s
plugins = %s

[log]
mode = console

[smtp]
enabled = true
host = %s:25
user = %s
password = %s
%s`, filepath.Join(dir, "data"), filepath.Join(dir, "logs"), filepath.Join(dir, "plugins"),
		remoteSMTPHost, smtpUserPlaceholder, smtpCredentialPlaceholder, policyLine)
	customPath := filepath.Join(dir, "grafana.ini")
	require.NoError(t, os.WriteFile(customPath, []byte(custom), 0o600))

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{
		HomePath: root,
		Config:   customPath,
	}))
	require.True(t, cfg.Smtp.Enabled)
	require.Equal(t, remoteSMTPHost+":25", cfg.Smtp.Host)
	require.Equal(t, smtpUserPlaceholder, cfg.Smtp.User)
	require.Equal(t, smtpCredentialPlaceholder, cfg.Smtp.Password)
	if startTLSPolicy == "" {
		require.Empty(t, cfg.Smtp.StartTLSPolicy)
	} else {
		require.Equal(t, startTLSPolicy, cfg.Smtp.StartTLSPolicy)
	}
	return cfg
}

func disclosedText(client []byte) string {
	var b strings.Builder
	b.Write(client)
	for _, line := range bytes.Split(client, []byte("\n")) {
		for _, field := range bytes.Fields(bytes.TrimSpace(line)) {
			if len(field) < 4 || len(field)%4 != 0 {
				continue
			}
			decoded, err := base64.StdEncoding.DecodeString(string(field))
			if err != nil || len(decoded) == 0 {
				continue
			}
			b.Write(decoded)
			b.WriteByte('\n')
		}
	}
	if body := smtpDataBody(client); len(body) > 0 {
		plain, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body)))
		if err == nil {
			b.Write(plain)
		}
	}
	return b.String()
}

func smtpDataBody(client []byte) []byte {
	idx := bytes.Index(client, []byte("DATA\r\n"))
	if idx < 0 {
		return nil
	}
	rest := client[idx+len("DATA\r\n"):]
	end := bytes.Index(rest, []byte("\r\n.\r\n"))
	if end < 0 {
		end = len(rest)
	}
	data := rest[:end]
	if split := bytes.Index(data, []byte("\r\n\r\n")); split >= 0 {
		return data[split+4:]
	}
	return data
}

func requireCleartextAbsent(t *testing.T, client []byte, needles ...string) {
	t.Helper()
	upper := bytes.ToUpper(client)
	if !bytes.Contains(upper, []byte("EHLO ")) && !bytes.Contains(upper, []byte("HELO ")) {
		t.Fatal("dialer never greeted the server")
	}
	text := disclosedText(client)
	authSent := false
	var messages []string
	for _, needle := range needles {
		if needle == "" || !strings.Contains(text, needle) {
			continue
		}
		if needle == smtpCredentialPlaceholder || needle == smtpUserPlaceholder {
			authSent = true
			continue
		}
		messages = append(messages, needle)
	}
	if authSent || len(messages) > 0 {
		t.Fatalf("cleartext dialogue before STARTTLS leaked authentication material=%v message content=%q", authSent, messages)
	}
}

func requireSendRefused(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("message was accepted by a server that did not advertise STARTTLS")
	}
	if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "i/o timeout") {
		t.Fatalf("dial did not reach the test server: %v", err)
	}
}

func TestMandatoryStartTLSPolicyDoesNotSendCleartext(t *testing.T) {
	srv := startCleartextSMTP(t)
	redirectSMTPDial(t, srv)
	cfg := loadEnabledSMTPConfig(t, "MandatoryStartTLS")
	client, err := NewSmtpClient(cfg.Smtp)
	require.NoError(t, err)

	_, err = client.Send(context.Background(), &Message{
		From:    cfg.Smtp.FromAddress,
		To:      []string{"rcpt@example.test"},
		Subject: "subject",
		Body:    map[string]string{"text/html": "mandatory-policy-body-marker"},
	})
	requireSendRefused(t, err)
	require.Equal(t, 1, srv.waitSessions(1, 3*time.Second))
	requireCleartextAbsent(t, srv.clientBytes(), smtpCredentialPlaceholder, "mandatory-policy-body-marker")
}

func TestNoStartTLSOptInStillDelivers(t *testing.T) {
	srv := startCleartextSMTP(t)
	redirectSMTPDial(t, srv)
	cfg := loadEnabledSMTPConfig(t, "NoStartTLS")
	client, err := NewSmtpClient(cfg.Smtp)
	require.NoError(t, err)

	count, err := client.Send(context.Background(), &Message{
		From:    cfg.Smtp.FromAddress,
		To:      []string{"rcpt@example.test"},
		Subject: "subject",
		Body:    map[string]string{"text/html": "nostarttls-body-marker"},
	})
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Equal(t, 1, srv.waitSessions(1, 3*time.Second))
	if !strings.Contains(disclosedText(srv.clientBytes()), "nostarttls-body-marker") {
		t.Fatal("explicit NoStartTLS did not deliver the message")
	}
}

func TestShippedEmptyStartTLSPolicyDoesNotSendCleartext(t *testing.T) {
	srv := startCleartextSMTP(t)
	redirectSMTPDial(t, srv)
	cfg := loadEnabledSMTPConfig(t, "")
	client, err := NewSmtpClient(cfg.Smtp)
	require.NoError(t, err)

	_, err = client.Send(context.Background(), &Message{
		From:    cfg.Smtp.FromAddress,
		To:      []string{"rcpt@example.test"},
		Subject: "subject",
		Body:    map[string]string{"text/html": "empty-policy-body-marker"},
	})
	requireSendRefused(t, err)
	require.Equal(t, 1, srv.waitSessions(1, 3*time.Second))
	requireCleartextAbsent(t, srv.clientBytes(), smtpCredentialPlaceholder, smtpUserPlaceholder, "empty-policy-body-marker")
}

func TestPasswordResetIsNotSentCleartextWhenStartTLSPolicyEmpty(t *testing.T) {
	ns, srv := newCleartextNotificationService(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ns.Run(ctx) }()

	err := ns.SendResetPasswordEmail(ctx, &SendResetPasswordEmailCommand{
		User: &user.User{
			ID:       7,
			Email:    "reset-recipient@example.test",
			Login:    "reset-recipient",
			Name:     "Reset Recipient",
			Password: user.Password("placeholder-user-secret"),
			Rands:    "placeholder-rands",
		},
	})
	require.NoError(t, err)
	require.Equal(t, 1, srv.waitSessions(1, 5*time.Second))
	requireCleartextAbsent(t, srv.clientBytes(), smtpCredentialPlaceholder, "user/password/reset?code=")
}

func TestInviteIsNotSentCleartextWhenStartTLSPolicyEmpty(t *testing.T) {
	ns, srv := newCleartextNotificationService(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ns.Run(ctx) }()

	err := ns.SendEmailCommandHandler(ctx, &SendEmailCommand{
		To:       []string{"invitee@example.test"},
		Template: "new_user_invite",
		Data: map[string]any{
			"Name":      "Invitee",
			"OrgName":   "Example Org",
			"Email":     "inviter@example.test",
			"LinkUrl":   "https://grafana.example/invite/invite-code-placeholder",
			"InvitedBy": "Inviter",
		},
	})
	require.NoError(t, err)
	require.Equal(t, 1, srv.waitSessions(1, 5*time.Second))
	requireCleartextAbsent(t, srv.clientBytes(), smtpCredentialPlaceholder, "invite-code-placeholder")
}

func TestSignupStartedIsNotSentCleartextWhenStartTLSPolicyEmpty(t *testing.T) {
	ns, srv := newCleartextNotificationService(t)
	ns.Cfg.VerifyEmailEnabled = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ns.Run(ctx) }()

	err := ns.signUpStartedHandler(ctx, &events.SignUpStarted{
		Email: "signup@example.test",
		Code:  "signup-code-placeholder",
	})
	require.NoError(t, err)
	require.Equal(t, 1, srv.waitSessions(1, 5*time.Second))
	requireCleartextAbsent(t, srv.clientBytes(), smtpCredentialPlaceholder, "signup-code-placeholder")
}

func TestVerificationEmailIsNotSentCleartextWhenStartTLSPolicyEmpty(t *testing.T) {
	ns, srv := newCleartextNotificationService(t)

	err := ns.SendVerificationEmail(context.Background(), &SendVerifyEmailCommand{
		User:  &user.User{Name: "Verify Recipient"},
		Email: "verify@example.test",
		Code:  "verify-code-placeholder",
	})
	requireSendRefused(t, err)
	require.Equal(t, 1, srv.waitSessions(1, 5*time.Second))
	requireCleartextAbsent(t, srv.clientBytes(), smtpCredentialPlaceholder, "verify-code-placeholder")
}

func TestAlertEmailSendIsNotCleartextWhenStartTLSPolicyEmpty(t *testing.T) {
	ns, srv := newCleartextNotificationService(t)

	err := ns.SendEmailCommandHandlerSync(context.Background(), &SendEmailCommandSync{
		SendEmailCommand: SendEmailCommand{
			To:          []string{"oncall@example.test"},
			SingleEmail: true,
			Template:    "alert_notification",
			Subject:     "firing",
			Data: map[string]any{
				"Message": "alert-body-marker",
				"Title":   "firing",
			},
		},
	})
	requireSendRefused(t, err)
	require.Equal(t, 1, srv.waitSessions(1, 5*time.Second))
	requireCleartextAbsent(t, srv.clientBytes(), smtpCredentialPlaceholder, "alert-body-marker")
}

type emailSentStore struct{}

func (emailSentStore) UpdateTempUserWithEmailSent(context.Context, *tempuser.UpdateTempUserWithEmailSentCommand) error {
	return nil
}

func newCleartextNotificationService(t *testing.T) (*NotificationService, *cleartextSMTP) {
	t.Helper()
	srv := startCleartextSMTP(t)
	redirectSMTPDial(t, srv)
	cfg := loadEnabledSMTPConfig(t, "")
	mailer, err := NewSmtpClient(cfg.Smtp)
	require.NoError(t, err)
	ns, err := ProvideService(bus.ProvideBus(nil), cfg, mailer, emailSentStore{})
	require.NoError(t, err)
	return ns, srv
}
