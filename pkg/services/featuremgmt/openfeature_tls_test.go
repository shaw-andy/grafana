package featuremgmt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/open-feature/go-sdk/openfeature"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/setting"
)

// placeholderExchangedCredential is the token-exchange response the features-service
// provider places on flag requests. It is not a real credential.
const placeholderExchangedCredential = "placeholder-exchanged-credential"

// placeholderSignerCredential is the signer configured for token exchange. It is not a real credential.
const placeholderSignerCredential = "placeholder-signer-credential"

// TestInitOpenFeatureWithCfgRejectsUntrustedFeatureFlagServer checks the production
// remote-provider setup used by the process-wide OpenFeature client. A feature-flag
// server that presents a certificate this process does not trust must not be able to
// supply flag values, including kubernetesSsoSettingsApi, and must not observe the
// token-exchange credential.
func TestInitOpenFeatureWithCfgRejectsUntrustedFeatureFlagServer(t *testing.T) {
	t.Cleanup(func() {
		require.NoError(t, openfeature.SetProviderAndWait(openfeature.NoopProvider{}))
	})

	flagBody := []byte(`{"key":"` + FlagKubernetesSsoSettingsApi + `","value":true,"reason":"STATIC","variant":"attacker-enabled"}`)

	t.Run("ofrep", func(t *testing.T) {
		srv := startUntrustedFlagServer(t, flagBody)
		cfg := openFeatureCfg(t, setting.OFREPProviderType, srv.url, "")
		require.NoError(t, InitOpenFeatureWithCfg(cfg))

		assertFlagServerUntrusted(t, srv)
	})

	t.Run("features-service", func(t *testing.T) {
		exchange := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"status":"ok","data":{"token":"`+placeholderExchangedCredential+`"}}`)
		}))
		t.Cleanup(exchange.Close)

		srv := startUntrustedFlagServer(t, flagBody)
		cfg := openFeatureCfg(t, setting.FeaturesServiceProviderType, srv.url, exchange.URL)
		require.NoError(t, InitOpenFeatureWithCfg(cfg))

		assertFlagServerUntrusted(t, srv)
		srv.mu.Lock()
		defer srv.mu.Unlock()
		for _, headers := range srv.headers {
			require.NotContains(t, headers.Values("X-Access-Token"), "Bearer "+placeholderExchangedCredential)
		}
	})
}

func assertFlagServerUntrusted(t *testing.T, srv *untrustedFlagServer) {
	t.Helper()

	ctx := context.Background()
	evalCtx := openfeature.TransactionContext(ctx)
	client := openfeature.NewDefaultClient()

	// Same call shape as IdentityAccessManagementAPIBuilder.featureEnabled.
	require.False(t, client.Boolean(ctx, FlagKubernetesSsoSettingsApi, false, evalCtx),
		"attacker flag adopted; requests=%d headers=%v", srv.requests(), srv.headerDump())

	details, err := client.BooleanValueDetails(ctx, FlagKubernetesSsoSettingsApi, false, evalCtx)
	require.Error(t, err)
	require.False(t, details.Value)
	var unknown x509.UnknownAuthorityError
	require.ErrorAs(t, err, &unknown)

	require.GreaterOrEqual(t, srv.accepted(), 1, "evaluation never attempted a TLS connection")
	require.Zero(t, srv.requests(), "untrusted server received an HTTP request: %v", srv.headerDump())
}

func openFeatureCfg(t *testing.T, provider setting.OpenFeatureProviderType, flagURL, exchangeURL string) *setting.Cfg {
	t.Helper()

	raw := fmt.Sprintf(`
[feature_toggles.openfeature]
provider = %s
url = %s
cache_ttl = 0
`, provider, flagURL)
	if provider == setting.FeaturesServiceProviderType {
		raw += fmt.Sprintf(`
[environment]
stack_id = 1

[grpc_client_authentication]
token = %s
token_exchange_url = %s
`, placeholderSignerCredential, exchangeURL)
	}

	cfg, err := setting.NewCfgFromBytes([]byte(raw))
	require.NoError(t, err)
	return cfg
}

type untrustedFlagServer struct {
	url          string
	accepts      int
	httpRequests int
	headers      []http.Header
	mu           sync.Mutex
}

func (s *untrustedFlagServer) accepted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepts
}

func (s *untrustedFlagServer) requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.httpRequests
}

func (s *untrustedFlagServer) headerDump() []http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]http.Header, len(s.headers))
	copy(out, s.headers)
	return out
}

func startUntrustedFlagServer(t *testing.T, body []byte) *untrustedFlagServer {
	t.Helper()

	cert := selfSignedServerCert(t)
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srvState := &untrustedFlagServer{}
	counting := &countingListener{Listener: inner, seen: srvState}

	tlsLn := tls.NewListener(counting, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	httpSrv := &http.Server{
		ErrorLog: log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			srvState.mu.Lock()
			srvState.httpRequests++
			srvState.headers = append(srvState.headers, r.Header.Clone())
			srvState.mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		}),
	}
	go func() {
		_ = httpSrv.Serve(tlsLn)
	}()
	t.Cleanup(func() {
		_ = httpSrv.Close()
	})

	srvState.url = "https://" + inner.Addr().String()
	return srvState
}

type countingListener struct {
	net.Listener
	seen *untrustedFlagServer
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.seen.mu.Lock()
	l.seen.accepts++
	l.seen.mu.Unlock()
	return c, nil
}

func selfSignedServerCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "untrusted-feature-flag.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
