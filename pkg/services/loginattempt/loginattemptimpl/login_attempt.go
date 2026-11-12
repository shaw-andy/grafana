package loginattemptimpl

import (
	"context"
	"hash/fnv"
	"strings"
	"sync"
	"time"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/serverlock"
	"github.com/grafana/grafana/pkg/services/loginattempt"
	"github.com/grafana/grafana/pkg/setting"
)

const loginAttemptsWindow = time.Minute * 5

func ProvideService(db db.DB, cfg *setting.Cfg, lock *serverlock.ServerLockService) *Service {
	return &Service{
		store:  &xormStore{db: db, now: time.Now},
		cfg:    cfg,
		lock:   lock,
		logger: log.New("login_attempt"),
	}
}

type Service struct {
	store  store
	cfg    *setting.Cfg
	lock   *serverlock.ServerLockService
	logger log.Logger

	userLocks stripedMutex
	ipLocks   stripedMutex
}

// stripedMutex serializes reservations that share a key within this process, with bounded memory.
type stripedMutex [256]sync.Mutex

func (m *stripedMutex) get(key string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &m[h.Sum32()%uint32(len(m))]
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

// Reserve inserts the attempt first and only then counts, so an attempt is always visible to
// the attempts counted after it. Within one process the per-key locks make the count exact.
// Across instances, concurrent attempts may see each other's rows and be rejected together,
// but no more than the limit can pass, because every passing attempt's row was committed
// before any later attempt counted.
func (s *Service) Reserve(ctx context.Context, username, ipAddress string) (int64, error) {
	checkUser := !s.cfg.DisableBruteForceLoginProtection && !s.cfg.DisableUsernameLoginProtection
	checkIP := !s.cfg.DisableBruteForceLoginProtection && !s.cfg.DisableIPAddressLoginProtection
	if !checkUser && !checkIP {
		return 0, nil
	}

	username = strings.ToLower(username)

	// Always lock the user before the IP address so two reservations cannot deadlock.
	if checkUser {
		m := s.userLocks.get(username)
		m.Lock()
		defer m.Unlock()
	}
	if checkIP {
		m := s.ipLocks.get(ipAddress)
		m.Lock()
		defer m.Unlock()
	}

	attempt, err := s.store.CreateLoginAttempt(ctx, CreateLoginAttemptCommand{
		Username:  username,
		IPAddress: ipAddress,
	})
	if err != nil {
		return 0, err
	}

	since := time.Now().Add(-loginAttemptsWindow)
	var blocked error
	if checkUser {
		count, err := s.store.GetUserLoginAttemptCount(ctx, GetUserLoginAttemptCountQuery{Username: username, Since: since})
		if err != nil {
			return 0, err
		}
		if count > s.cfg.BruteForceLoginProtectionMaxAttempts {
			blocked = loginattempt.ErrTooManyUserAttempts
		}
	}
	if blocked == nil && checkIP {
		count, err := s.store.GetIPLoginAttemptCount(ctx, GetIPLoginAttemptCountQuery{IPAddress: ipAddress, Since: since})
		if err != nil {
			return 0, err
		}
		if count > s.cfg.BruteForceLoginProtectionMaxAttempts {
			blocked = loginattempt.ErrTooManyIPAttempts
		}
	}

	if blocked != nil {
		// A rejected attempt never reaches the password check, so it must not extend the lockout.
		if err := s.store.DeleteLoginAttempt(ctx, attempt.Id); err != nil {
			return 0, err
		}
		return 0, blocked
	}

	return attempt.Id, nil
}

func (s *Service) Release(ctx context.Context, attemptID int64) error {
	if attemptID == 0 {
		return nil
	}
	return s.store.DeleteLoginAttempt(ctx, attemptID)
}

func (s *Service) Reset(ctx context.Context, username string) error {
	return s.store.DeleteLoginAttempts(ctx, DeleteLoginAttemptsCommand{strings.ToLower(username)})
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
