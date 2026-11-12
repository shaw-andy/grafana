package loginattempttest

import (
	"context"
	"net/http"

	"github.com/grafana/grafana/pkg/services/loginattempt"
)

var _ loginattempt.Service = new(MockLoginAttemptService)

type MockLoginAttemptService struct {
	AddCalled      bool
	ResetCalled    bool
	ValidateCalled bool

	ExpectedValid bool
	ExpectedErr   error
}

func (f *MockLoginAttemptService) ClientIPAddress(r *http.Request) string {
	return r.RemoteAddr
}

func (f *MockLoginAttemptService) Add(ctx context.Context, username, ipAddress string) error {
	f.AddCalled = true
	return f.ExpectedErr
}

func (f *MockLoginAttemptService) Reset(ctx context.Context, username string) error {
	f.ResetCalled = true
	return f.ExpectedErr
}

func (f *MockLoginAttemptService) Validate(ctx context.Context, username string) (bool, error) {
	f.ValidateCalled = true
	return f.ExpectedValid, f.ExpectedErr
}

func (f *MockLoginAttemptService) ValidateIPAddress(ctx context.Context, ipAddress string) (bool, error) {
	f.ValidateCalled = true
	return f.ExpectedValid, f.ExpectedErr
}
