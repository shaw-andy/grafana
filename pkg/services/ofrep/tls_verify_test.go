package ofrep

import (
	"bytes"
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

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
)

// placeholderCallerCredential is a caller-supplied credential the OFREP proxy would
// forward upstream. It is not a real credential.
const placeholderCallerCredential = "placeholder-caller-credential"

// TestProvideServiceRejectsUntrustedFeatureFlagServer checks the OFREP proxy built by
// ProvideService. That proxy dials the configured feature-flag URL with its own HTTP
// transport. An untrusted certificate must stop the request before the upstream
// observes the caller's credential or returns a flag value.
func TestProvideServiceRejectsUntrustedFeatureFlagServer(t *testing.T) {
	providers := []setting.OpenFeatureProviderType{
		setting.OFREPProviderType,
		setting.FeaturesServiceProviderType,
	}
	for _, provider := range providers {
		t.Run(string(provider), func(t *testing.T) {
			t.Run("one flag", func(t *testing.T) {
				const marker = "attacker-enabled"
				body := []byte(`{"key":"` + featuremgmt.FlagKubernetesSsoSettingsApi + `","value":true,"reason":"STATIC","variant":"` + marker + `","metadata":{"public":true}}`)
				srv := startUntrustedFlagServer(t, body)
				builder := proxyBuilder(t, provider, srv.url)

				req := authedEvalRequest(t, "/ofrep/v1/evaluate/flags/"+featuremgmt.FlagKubernetesSsoSettingsApi, map[string]string{
					"flagKey": featuremgmt.FlagKubernetesSsoSettingsApi,
				})
				w := httptest.NewRecorder()
				builder.oneFlagHandler(w, req)
				assertProxyRejected(t, srv, w, marker)
			})

			t.Run("all flags", func(t *testing.T) {
				const marker = "attacker-enabled"
				body := []byte(`{"flags":[{"key":"` + featuremgmt.FlagKubernetesSsoSettingsApi + `","value":true,"reason":"STATIC","variant":"` + marker + `","metadata":{"public":true}}]}`)
				srv := startUntrustedFlagServer(t, body)
				builder := proxyBuilder(t, provider, srv.url)

				req := authedEvalRequest(t, "/ofrep/v1/evaluate/flags", nil)
				w := httptest.NewRecorder()
				builder.allFlagsHandler(w, req)
				assertProxyRejected(t, srv, w, marker)
			})
		})
	}
}

func assertProxyRejected(t *testing.T, srv *untrustedFlagServer, w *httptest.ResponseRecorder, marker string) {
	t.Helper()

	require.NotContains(t, w.Body.String(), marker)
	require.NotEqual(t, http.StatusOK, w.Code)
	require.GreaterOrEqual(t, srv.accepted(), 1, "proxy never attempted a TLS connection")
	require.Zero(t, srv.requests(), "untrusted server received an HTTP request")
	for _, headers := range srv.seenHeaders() {
		require.NotContains(t, headers.Values("Authorization"), "Bearer "+placeholderCallerCredential)
		require.NotContains(t, headers.Values("X-Access-Token"), "Bearer "+placeholderCallerCredential)
	}
}

func proxyBuilder(t *testing.T, provider setting.OpenFeatureProviderType, flagURL string) *APIBuilder {
	t.Helper()
	raw := fmt.Sprintf(`
[feature_toggles.openfeature]
provider = %s
url = %s
`, provider, flagURL)
	cfg, err := setting.NewCfgFromBytes([]byte(raw))
	require.NoError(t, err)
	builder, err := ProvideService(cfg, routing.ProvideRegister())
	require.NoError(t, err)
	return builder
}

func authedEvalRequest(t *testing.T, target string, vars map[string]string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, bytes.NewBufferString(`{"context":{"namespace":"stacks-1"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+placeholderCallerCredential)
	req.Header.Set("X-Access-Token", "Bearer "+placeholderCallerCredential)
	if len(vars) > 0 {
		req = mux.SetURLVars(req, vars)
	}
	requester := &identity.StaticRequester{
		Type:      types.TypeUser,
		UserID:    1,
		OrgID:     1,
		Namespace: "stacks-1",
	}
	return req.WithContext(types.WithAuthInfo(req.Context(), requester))
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

func (s *untrustedFlagServer) seenHeaders() []http.Header {
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

	state := &untrustedFlagServer{url: "https://" + inner.Addr().String()}
	tlsLn := tls.NewListener(&countingListener{Listener: inner, seen: state}, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	httpSrv := &http.Server{
		ErrorLog: log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			state.mu.Lock()
			state.httpRequests++
			state.headers = append(state.headers, r.Header.Clone())
			state.mu.Unlock()
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
	return state
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
