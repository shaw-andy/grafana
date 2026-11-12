package clients

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel/trace"

	"github.com/grafana/grafana/pkg/apimachinery/errutil"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/loginattempt"
	"github.com/grafana/grafana/pkg/web"
)

var (
	errInvalidPassword                    = errutil.Unauthorized("password-auth.invalid", errutil.WithPublicMessage("Invalid password or username"))
	errPasswordAuthFailed                 = errutil.Unauthorized("password-auth.failed", errutil.WithPublicMessage("Invalid username or password"))
	errPasswordClientTooManyLoginAttempts = errutil.Unauthorized("login-attempt.blocked", errutil.WithPublicMessage("Login temporarily blocked"))
)

var _ authn.PasswordClient = new(Password)

func ProvidePassword(loginAttempts loginattempt.Service, tracer trace.Tracer, clients ...authn.PasswordClient) *Password {
	return &Password{loginAttempts, clients, log.New("authn.password"), tracer}
}

type Password struct {
	loginAttempts loginattempt.Service
	clients       []authn.PasswordClient
	log           log.Logger
	tracer        trace.Tracer
}

func (c *Password) AuthenticatePassword(ctx context.Context, r *authn.Request, username, password string) (*authn.Identity, error) {
	ctx, span := c.tracer.Start(ctx, "authn.password.AuthenticatePassword")
	defer span.End()
	r.SetMeta(authn.MetaKeyUsername, username)

	if len(password) == 0 {
		return nil, errPasswordAuthFailed.Errorf("no password provided")
	}

	attemptID, err := c.loginAttempts.Reserve(ctx, username, web.RemoteAddr(r.HTTPRequest))
	switch {
	case errors.Is(err, loginattempt.ErrTooManyUserAttempts):
		return nil, errPasswordAuthFailed.Errorf("too many consecutive incorrect login attempts for user - login for user temporarily blocked")
	case errors.Is(err, loginattempt.ErrTooManyIPAttempts):
		return nil, errPasswordClientTooManyLoginAttempts.Errorf("too many consecutive incorrect login attempts for IP address - login for IP address temporarily blocked")
	case err != nil:
		return nil, err
	}

	var clientErrs error
	for _, pwClient := range c.clients {
		identity, clientErr := pwClient.AuthenticatePassword(ctx, r, username, password)
		clientErrs = errors.Join(clientErrs, clientErr)
		// we always try next client on any error
		if clientErr != nil {
			c.log.FromContext(ctx).Debug("Failed to authenticate password identity", "client", pwClient, "error", clientErr)
			continue
		}

		if identity == nil {
			continue
		}

		if err := c.loginAttempts.Release(context.WithoutCancel(ctx), attemptID); err != nil {
			c.log.FromContext(ctx).Warn("Failed to release login attempt after successful login", "error", err)
		}
		return identity, nil
	}

	return nil, errPasswordAuthFailed.Errorf("failed to authenticate identity: %w", clientErrs)
}
