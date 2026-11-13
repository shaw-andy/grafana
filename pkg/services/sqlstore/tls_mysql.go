package sqlstore

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/grafana/grafana/pkg/infra/log"
)

var tlslog = log.New("tls_mysql")

func makeCert(config *DatabaseConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{}
	if config.CaCertPath != "" {
		rootCertPool := x509.NewCertPool()
		pem, err := os.ReadFile(config.CaCertPath)
		if err != nil {
			return nil, fmt.Errorf("could not read DB CA Cert path %q: %w", config.CaCertPath, err)
		}
		if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
			return nil, fmt.Errorf("could not parse DB CA Cert path %q", config.CaCertPath)
		}
		tlsConfig.RootCAs = rootCertPool
	}
	if config.ClientCertPath != "" && config.ClientKeyPath != "" {
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			tlslog.Debug("Loading client certificate")
			cert, err := tls.LoadX509KeyPair(config.ClientCertPath, config.ClientKeyPath)
			return &cert, err
		}
	}
	// With an empty ServerName the driver verifies the certificate against the host name it dials.
	tlsConfig.ServerName = config.ServerCertName
	if config.SslMode == "skip-verify" {
		tlsConfig.InsecureSkipVerify = true
	}
	return tlsConfig, nil
}
