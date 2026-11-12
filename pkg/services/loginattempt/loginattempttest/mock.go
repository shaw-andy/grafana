package loginattempttest

import (
	"context"

	"github.com/grafana/grafana/pkg/services/loginattempt"
)

var _ loginattempt.Service = new(MockLoginAttemptService)

type MockLoginAttemptService struct {
	ReserveCalled bool
	ReleaseCalled bool
	ResetCalled   bool

	ExpectedValid bool
	ExpectedErr   error
}

func (f *MockLoginAttemptService) Reserve(ctx context.Context, username, ipAddress string) (int64, error) {
	f.ReserveCalled = true
	if f.ExpectedErr != nil {
		return 0, f.ExpectedErr
	}
	if !f.ExpectedValid {
		return 0, loginattempt.ErrTooManyUserAttempts
	}
	return 0, nil
}

func (f *MockLoginAttemptService) Release(ctx context.Context, attemptID int64) error {
	f.ReleaseCalled = true
	return f.ExpectedErr
}

func (f *MockLoginAttemptService) Reset(ctx context.Context, username string) error {
	f.ResetCalled = true
	return f.ExpectedErr
}
