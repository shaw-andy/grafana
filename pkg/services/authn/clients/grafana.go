package clients

import (
	"context"
	"errors"
	"net/mail"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/trace"

	claims "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
)

var _ authn.ProxyClient = new(Grafana)
var _ authn.PasswordClient = new(Grafana)

// dummyPasswordHash never matches. Verifying against it when there is no stored
// hash to check costs the same as a real check, so response time does not tell
// whether the user exists or has a password.
var dummyPasswordHash = "pbkdf2-sha256$600000$" + strings.Repeat("0", 64)

func ProvideGrafana(cfg *setting.Cfg, userService user.Service, tracer trace.Tracer) *Grafana {
	return &Grafana{cfg, userService, tracer, log.New("authn.grafana")}
}

type Grafana struct {
	cfg         *setting.Cfg
	userService user.Service
	tracer      trace.Tracer
	log         log.Logger
}

func (c *Grafana) String() string {
	return "grafana"
}

func (c *Grafana) AuthenticateProxy(ctx context.Context, r *authn.Request, username string, additional map[string]string) (*authn.Identity, error) {
	ctx, span := c.tracer.Start(ctx, "authn.grafana.AuthenticateProxy") //nolint:ineffassign,staticcheck
	defer span.End()

	identity := &authn.Identity{
		AuthenticatedBy: login.AuthProxyAuthModule,
		AuthID:          username,
		ClientParams: authn.ClientParams{
			SyncUser:        true,
			SyncTeams:       true,
			FetchSyncedUser: true,
			SyncOrgRoles:    true,
			SyncPermissions: true,
			AllowSignUp:     c.cfg.AuthProxy.AutoSignUp,
		},
	}

	switch c.cfg.AuthProxy.HeaderProperty {
	case "username":
		identity.Login = username
		addr, err := mail.ParseAddress(username)
		if err == nil {
			identity.Email = addr.Address
		}
	case "email":
		identity.Login = username
		identity.Email = username
	default:
		return nil, errInvalidProxyHeader.Errorf("invalid auth proxy header property, expected username or email but got: %s", c.cfg.AuthProxy.HeaderProperty)
	}

	if v, ok := additional[proxyFieldName]; ok {
		identity.Name = v
	}

	if v, ok := additional[proxyFieldEmail]; ok {
		identity.Email = v
	}

	if v, ok := additional[proxyFieldLogin]; ok {
		identity.Login = v
	}

	if v, ok := additional[proxyFieldRole]; ok {
		orgRoles, isGrafanaAdmin, _ := getRoles(c.cfg, func() (org.RoleType, *bool, error) {
			return org.RoleType(v), nil, nil
		})
		identity.OrgRoles = orgRoles
		identity.IsGrafanaAdmin = isGrafanaAdmin
	}

	if v, ok := additional[proxyFieldGroups]; ok {
		identity.ExternalGroups = util.SplitString(v)
	}

	identity.ClientParams.LookUpParams.Email = &identity.Email
	identity.ClientParams.LookUpParams.Login = &identity.Login

	return identity, nil
}

func (c *Grafana) AuthenticatePassword(ctx context.Context, r *authn.Request, username, password string) (*authn.Identity, error) {
	ctx, span := c.tracer.Start(ctx, "authn.grafana.AuthenticatePassword")
	defer span.End()

	usr, err := c.userService.GetByLoginWithPassword(ctx, &user.GetUserByLoginQuery{LoginOrEmail: username})
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			util.VerifyPassword(password, "", dummyPasswordHash)
			return nil, errIdentityNotFound.Errorf("no user found: %w", err)
		}
		return nil, err
	}

	// user was found so set auth module in req metadata
	r.SetMeta(authn.MetaKeyAuthModule, "grafana")

	if usr.Password == "" {
		util.VerifyPassword(password, "", dummyPasswordHash)
		return nil, errInvalidPassword.Errorf("invalid password")
	}

	match, needsRehash := user.Password(password).Verify(usr.Salt, usr.Password)
	if !match {
		return nil, errInvalidPassword.Errorf("invalid password")
	}

	if needsRehash {
		if err := c.userService.RehashPassword(ctx, &user.RehashPasswordCommand{
			UserID:      usr.ID,
			Salt:        usr.Salt,
			Password:    user.Password(password),
			CurrentHash: usr.Password,
		}); err != nil {
			c.log.FromContext(ctx).Warn("Failed to upgrade stored password hash", "userID", usr.ID, "error", err)
		}
	}

	return &authn.Identity{
		ID:              strconv.FormatInt(usr.ID, 10),
		Type:            claims.TypeUser,
		OrgID:           r.OrgID,
		ClientParams:    authn.ClientParams{FetchSyncedUser: true, SyncPermissions: true},
		AuthenticatedBy: login.PasswordAuthModule,
	}, nil
}
