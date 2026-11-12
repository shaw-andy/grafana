package loginattempttest

import (
	"context"

	"github.com/grafana/grafana/pkg/services/loginattempt"
)

var _ loginattempt.Service = new(FakeLoginAttemptService)

type FakeLoginAttemptService struct {
	ExpectedValid bool
	ExpectedErr   error
}

func (f FakeLoginAttemptService) Reserve(ctx context.Context, username, ipAddress string) (int64, error) {
	if f.ExpectedErr != nil {
		return 0, f.ExpectedErr
	}
	if !f.ExpectedValid {
		return 0, loginattempt.ErrTooManyUserAttempts
	}
	return 0, nil
}

func (f FakeLoginAttemptService) Release(ctx context.Context, attemptID int64) error {
	return f.ExpectedErr
}

func (f FakeLoginAttemptService) Reset(ctx context.Context, username string) error {
	return f.ExpectedErr
}
