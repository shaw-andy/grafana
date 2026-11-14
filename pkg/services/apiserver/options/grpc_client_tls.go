package options

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/grafana/grafana/pkg/setting"
)

// GrpcClientTLSConfig is the transport security of gRPC connections to the
// unified storage and search servers.
type GrpcClientTLSConfig struct {
	Enabled bool
	// CAFile is a PEM bundle of the CAs trusted to sign the server certificate.
	// When empty, the system roots are used.
	CAFile string
	// ServerName is checked against the server certificate. When empty, the host
	// of the dialed address is used.
	ServerName string
}

// ReadGrpcClientTLSConfig reads the gRPC client TLS settings from [grafana-apiserver].
func ReadGrpcClientTLSConfig(cfg *setting.Cfg) GrpcClientTLSConfig {
	sec := cfg.SectionWithEnvOverrides("grafana-apiserver")
	return GrpcClientTLSConfig{
		Enabled:    sec.Key("grpc_client_tls_enabled").MustBool(false),
		CAFile:     sec.Key("grpc_client_tls_ca_file").MustString(""),
		ServerName: sec.Key("grpc_client_tls_server_name").MustString(""),
	}
}

// TransportCredentials returns the credentials to dial targets with.
//
// With TLS enabled the server certificate is always verified. Without TLS, a
// target that is not a loopback address, localhost, or a unix socket is refused,
// and the returned credentials still refuse any connection whose peer is not on
// the local host, since a name that looks local may resolve elsewhere.
func (c GrpcClientTLSConfig) TransportCredentials(targets ...string) (credentials.TransportCredentials, error) {
	if c.Enabled {
		return c.tlsCredentials()
	}
	for _, target := range targets {
		if target != "" && !IsLocalGrpcTarget(target) {
			return nil, fmt.Errorf("refusing plaintext gRPC connection to non-loopback address %q: TLS is not enabled", target)
		}
	}
	return localOnlyCredentials{TransportCredentials: insecure.NewCredentials()}, nil
}

func (c GrpcClientTLSConfig) tlsCredentials() (credentials.TransportCredentials, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: c.ServerName,
	}
	if c.CAFile != "" {
		// nolint:gosec // The CA path comes from operator configuration.
		caPEM, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read gRPC client TLS CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("gRPC client TLS CA file %q contains no PEM certificates", c.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	return credentials.NewTLS(tlsCfg), nil
}

// IsLocalGrpcTarget reports whether a gRPC target names the local host: a unix
// socket, localhost, a loopback IP, or an empty or unspecified host. Targets
// using any other resolver scheme are not considered local.
func IsLocalGrpcTarget(target string) bool {
	endpoint := target
	if u, err := url.Parse(target); err == nil {
		switch u.Scheme {
		case "unix", "unix-abstract":
			return true
		case "dns", "passthrough":
			endpoint = strings.TrimPrefix(u.Path, "/")
			if endpoint == "" {
				endpoint = u.Opaque
			}
		}
	}

	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if host == "" || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// localOnlyCredentials are plaintext credentials that refuse the handshake
// before any byte is written when the connected peer is not on the local host.
type localOnlyCredentials struct {
	credentials.TransportCredentials
}

func (c localOnlyCredentials) ClientHandshake(ctx context.Context, authority string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if !isLocalPeer(conn.RemoteAddr()) {
		return nil, nil, fmt.Errorf("refusing plaintext gRPC connection to non-loopback peer %s: TLS is not enabled", conn.RemoteAddr())
	}
	return c.TransportCredentials.ClientHandshake(ctx, authority, conn)
}

func (c localOnlyCredentials) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("client-only gRPC credentials cannot be used by a server")
}

func (c localOnlyCredentials) Clone() credentials.TransportCredentials {
	return localOnlyCredentials{TransportCredentials: c.TransportCredentials.Clone()}
}

// refusingCredentials fail every handshake with err before any byte is written.
type refusingCredentials struct {
	err error
}

func (c refusingCredentials) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, c.err
}

func (c refusingCredentials) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, c.err
}

func (c refusingCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls"}
}

func (c refusingCredentials) Clone() credentials.TransportCredentials { return c }

func (c refusingCredentials) OverrideServerName(string) error { return nil }

func isLocalPeer(addr net.Addr) bool {
	switch a := addr.(type) {
	case *net.UnixAddr:
		return true
	case *net.TCPAddr:
		return a.IP.IsLoopback()
	}
	if addr == nil {
		return false
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
