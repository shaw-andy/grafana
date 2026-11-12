package loginattemptimpl

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/serverlock"
	"github.com/grafana/grafana/pkg/setting"
)

const loginAttemptsWindow = time.Minute * 5

func ProvideService(db db.DB, cfg *setting.Cfg, lock *serverlock.ServerLockService) *Service {
	return &Service{
		&xormStore{db: db, now: time.Now},
		cfg,
		lock,
		log.New("login_attempt"),
	}
}

type Service struct {
	store  store
	cfg    *setting.Cfg
	lock   *serverlock.ServerLockService
	logger log.Logger
}

func (s *Service) Run(ctx context.Context) error {
	// no need to run clean up job if it is disabled
	if s.cfg.DisableBruteForceLoginProtection {
		return nil
	}

	ticker := time.NewTicker(time.Minute * 10)
	for {
		select {
		case <-ticker.C:
			s.cleanup(ctx)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *Service) ClientIPAddress(r *http.Request) string {
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	peerIP := net.ParseIP(peer)
	if peerIP == nil {
		// Unix socket connections do not carry an IP address and can only come
		// from the local host.
		peerIP = net.IPv4(127, 0, 0, 1)
	}
	if !s.isTrustedProxy(peerIP) {
		return attemptAddress(peerIP)
	}

	// Each proxy appends the address it received the request from, so entries
	// left of the last untrusted hop can be set by the client.
	var hops []string
	for _, value := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(value, ",")...)
	}
	client := peerIP
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(hops[i]))
		if ip == nil {
			break
		}
		client = ip
		if !s.isTrustedProxy(ip) {
			return attemptAddress(client)
		}
	}
	if len(hops) > 0 {
		return attemptAddress(client)
	}

	if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); ip != nil {
		return attemptAddress(ip)
	}
	return attemptAddress(peerIP)
}

// attemptAddress counts IPv6 clients by their /64 prefix, since a single host
// is usually assigned a whole /64 and could otherwise rotate addresses freely.
func attemptAddress(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	prefix := net.IPNet{IP: ip.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}
	return prefix.String()
}

func (s *Service) isTrustedProxy(ip net.IP) bool {
	for _, ipNet := range s.cfg.IPAddressLoginProtectionTrustedProxies {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Service) Add(ctx context.Context, username, IPAddress string) error {
	if s.cfg.DisableBruteForceLoginProtection || (s.cfg.DisableUsernameLoginProtection && s.cfg.DisableIPAddressLoginProtection) {
		return nil
	}

	_, err := s.store.CreateLoginAttempt(ctx, CreateLoginAttemptCommand{
		Username:  strings.ToLower(username),
		IPAddress: IPAddress,
	})
	return err
}

func (s *Service) Reset(ctx context.Context, username string) error {
	return s.store.DeleteLoginAttempts(ctx, DeleteLoginAttemptsCommand{strings.ToLower(username)})
}

func (s *Service) Validate(ctx context.Context, username string) (bool, error) {
	if s.cfg.DisableBruteForceLoginProtection || s.cfg.DisableUsernameLoginProtection {
		return true, nil
	}

	loginAttemptCountQuery := GetUserLoginAttemptCountQuery{
		Username: strings.ToLower(username),
		Since:    time.Now().Add(-loginAttemptsWindow),
	}

	count, err := s.store.GetUserLoginAttemptCount(ctx, loginAttemptCountQuery)
	if err != nil {
		return false, err
	}

	if count >= s.cfg.BruteForceLoginProtectionMaxAttempts {
		return false, nil
	}

	return true, nil
}

func (s *Service) ValidateIPAddress(ctx context.Context, IPAddress string) (bool, error) {
	if s.cfg.DisableBruteForceLoginProtection || s.cfg.DisableIPAddressLoginProtection {
		return true, nil
	}

	loginAttemptCountQuery := GetIPLoginAttemptCountQuery{
		IPAddress: IPAddress,
		Since:     time.Now().Add(-loginAttemptsWindow),
	}

	count, err := s.store.GetIPLoginAttemptCount(ctx, loginAttemptCountQuery)
	if err != nil {
		return false, err
	}

	if count >= s.cfg.BruteForceLoginProtectionMaxAttempts {
		return false, nil
	}

	return true, nil
}

func (s *Service) cleanup(ctx context.Context) {
	err := s.lock.LockAndExecute(ctx, "delete old login attempts", time.Minute*10, func(context.Context) {
		cmd := DeleteOldLoginAttemptsCommand{
			OlderThan: time.Now().Add(time.Minute * -10),
		}
		if deletedLogs, err := s.store.DeleteOldLoginAttempts(ctx, cmd); err != nil {
			s.logger.Error("Problem deleting expired login attempts", "error", err.Error())
		} else {
			s.logger.Debug("Deleted expired login attempts", "rows affected", deletedLogs)
		}
	})

	if err != nil {
		s.logger.Error("Failed to lock and execute cleanup of old login attempts", "error", err)
	}
}
