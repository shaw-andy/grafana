package loginattempt

import (
	"context"
	"errors"
)

var (
	ErrTooManyUserAttempts = errors.New("too many login attempts for user")
	ErrTooManyIPAttempts   = errors.New("too many login attempts for IP address")
)

type Service interface {
	// Reserve records a login attempt for username and ipAddress before the credentials are checked.
	// It returns ErrTooManyUserAttempts or ErrTooManyIPAttempts, and records nothing, when the
	// attempt would exceed the limit. A reserved attempt counts as a failed login until it is released.
	// The returned id is 0 when nothing was recorded.
	Reserve(ctx context.Context, username, ipAddress string) (int64, error)
	// Release removes a reserved attempt, used once the login it was reserved for succeeded.
	Release(ctx context.Context, attemptID int64) error
	// Reset resets all login attempts attached to username
	Reset(ctx context.Context, username string) error
}

type LoginAttempt struct {
	Id        int64
	Username  string
	IpAddress string
	Created   int64
}
