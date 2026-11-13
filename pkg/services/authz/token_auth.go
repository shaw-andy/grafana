package authz

import (
	"context"
	"crypto/tls"

	"github.com/grafana/authlib/authn"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// TODO: move this to authlib
func NewGRPCTokenAuth(audience, namespace string, tc authn.TokenExchanger) *tokenAuth {
	return &tokenAuth{audience: audience, namespace: namespace, tokenClient: tc}
}

type tokenAuth struct {
	audience    string
	namespace   string
	tokenClient authn.TokenExchanger
	// allowInsecure lets gRPC attach the token to a plaintext connection.
	// It must only be set when the operator explicitly opted out of TLS.
	allowInsecure bool
}

func (t *tokenAuth) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	token, err := t.tokenClient.Exchange(ctx, authn.TokenExchangeRequest{
		Namespace: t.namespace,
		Audiences: []string{t.audience},
	})
	if err != nil {
		return nil, err
	}

	const metadataKey = "X-Access-Token"

	return map[string]string{metadataKey: token.Token}, nil
}

func (t *tokenAuth) RequireTransportSecurity() bool { return !t.allowInsecure }

// newRemoteAuthzCredentials returns the transport and per-RPC credentials used by
// the remote authorization clients. TLS is used unless no cert file is configured
// and allowInsecure is explicitly set; without a cert file the system roots verify
// the server.
func newRemoteAuthzCredentials(certFile string, allowInsecure bool, namespace string, tc authn.TokenExchanger) (credentials.TransportCredentials, *tokenAuth, error) {
	tokenCreds := NewGRPCTokenAuth(AuthzServiceAudience, namespace, tc)

	if certFile != "" {
		transportCreds, err := credentials.NewClientTLSFromFile(certFile, "")
		if err != nil {
			return nil, nil, err
		}
		return transportCreds, tokenCreds, nil
	}

	if allowInsecure {
		tokenCreds.allowInsecure = true
		return insecure.NewCredentials(), tokenCreds, nil
	}

	return credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}), tokenCreds, nil
}
