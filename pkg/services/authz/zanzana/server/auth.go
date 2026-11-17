package server

import (
	"context"
	"slices"

	claims "github.com/grafana/authlib/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/authz/zanzana"
	"github.com/grafana/grafana/pkg/setting"
)

// skipAuthorization must match the condition under which the gRPC server swaps
// in a no-op authenticator. Outside development the token is still verified, so
// its namespace has to be enforced even when allow_insecure is set.
func skipAuthorization(cfg *setting.Cfg) bool {
	return cfg.ZanzanaServer.AllowInsecure && cfg.Env == setting.Dev
}

func authorize(ctx context.Context, namespace string, skip bool) error {
	logger := log.New("zanzana.server.auth")
	if skip {
		logger.Debug("AllowInsecure=true in development; skipping authorization check")
		return nil
	}
	c, ok := claims.AuthInfoFrom(ctx)
	if !ok {
		return status.Errorf(codes.Unauthenticated, "unauthenticated")
	}
	if c.GetNamespace() == "" || namespace == "" {
		return status.Errorf(codes.Unauthenticated, "unauthenticated")
	}
	if !claims.NamespaceMatches(c.GetNamespace(), namespace) {
		return status.Errorf(codes.PermissionDenied, "token namespace %s does not match request namespace", c.GetNamespace())
	}
	return nil
}

func authorizeWrite(ctx context.Context, namespace string, skip bool) error {
	if err := authorize(ctx, namespace, skip); err != nil {
		return err
	}

	c, ok := claims.AuthInfoFrom(ctx)
	if !ok {
		return status.Errorf(codes.Unauthenticated, "unauthenticated")
	}

	if !slices.Contains(c.GetTokenPermissions(), zanzana.TokenPermissionUpdate) {
		return status.Errorf(codes.PermissionDenied, "missing token permission %s", zanzana.TokenPermissionUpdate)
	}

	return nil
}
