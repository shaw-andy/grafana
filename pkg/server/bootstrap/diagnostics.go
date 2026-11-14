package bootstrap

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"runtime/trace"
	"strconv"
	"strings"
	"time"

	deltapprof "github.com/grafana/pyroscope-go/godeltaprof/http/pprof"

	"github.com/grafana/grafana/pkg/infra/log"
)

const (
	profilingEnabledEnvName   = "GF_DIAGNOSTICS_PROFILING_ENABLED"
	profilingAddrEnvName      = "GF_DIAGNOSTICS_PROFILING_ADDR"
	profilingPortEnvName      = "GF_DIAGNOSTICS_PROFILING_PORT"
	profilingBlockRateEnvName = "GF_DIAGNOSTICS_PROFILING_BLOCK_RATE"
	profilingMutexRateEnvName = "GF_DIAGNOSTICS_PROFILING_MUTEX_RATE"
	profilingTokenFileEnvName = "GF_DIAGNOSTICS_PROFILING_TOKEN_FILE"
	tracingEnabledEnvName     = "GF_DIAGNOSTICS_TRACING_ENABLED"
	tracingFileEnvName        = "GF_DIAGNOSTICS_TRACING_FILE"
)

const (
	profilingReadTimeout = 3 * time.Second
	profilingIdleTimeout = 3 * time.Second
	// net/http/pprof extends the write deadline by the requested duration for
	// CPU profiles and traces, so this does not cap ?seconds=N.
	profilingWriteTimeout   = 5 * time.Second
	profilingMinTokenLength = 16
)

// Diagnostics holds the CPU-profiling (pprof) and execution-tracing inputs the
// bootstrap process configures at startup. Values originate from CLI flags but
// are passed as plain data so bootstrap does not depend on the CLI layer.
type Diagnostics struct {
	Profile              bool
	ProfileAddr          string
	ProfilePort          uint64
	ProfileBlockRate     int
	ProfileMutexFraction int
	ProfileTokenFile     string
	Tracing              bool
	TracingFile          string
}

type profilingDiagnostics struct {
	enabled   bool
	addr      string
	port      uint64
	blockRate int
	mutexRate int
	tokenFile string
}

func newProfilingDiagnostics(enabled bool, addr string, port uint64, blockRate int, mutexRate int) *profilingDiagnostics {
	return &profilingDiagnostics{
		enabled:   enabled,
		addr:      addr,
		port:      port,
		blockRate: blockRate,
		mutexRate: mutexRate,
	}
}

func (pd *profilingDiagnostics) overrideWithEnv() error {
	enabledEnv := os.Getenv(profilingEnabledEnvName)
	if enabledEnv != "" {
		enabled, err := strconv.ParseBool(enabledEnv)
		if err != nil {
			return fmt.Errorf("failed to parse %s environment variable as bool", profilingEnabledEnvName)
		}
		pd.enabled = enabled
	}

	addrEnv := os.Getenv(profilingAddrEnvName)
	if addrEnv != "" {
		pd.addr = addrEnv
	}

	portEnv := os.Getenv(profilingPortEnvName)
	if portEnv != "" {
		port, parseErr := strconv.ParseUint(portEnv, 0, 64)
		if parseErr != nil {
			return fmt.Errorf("failed to parse %s environment variable to unsigned integer", profilingPortEnvName)
		}
		pd.port = port
	}

	blockRateEnv := os.Getenv(profilingBlockRateEnvName)
	if blockRateEnv != "" {
		blockRate, err := strconv.Atoi(blockRateEnv)
		if err != nil {
			return fmt.Errorf("failed to parse %s environment variable as int", profilingBlockRateEnvName)
		}
		pd.blockRate = blockRate
	}

	mutexFractionEnv := os.Getenv(profilingMutexRateEnvName)
	if mutexFractionEnv != "" {
		mutexProfileFraction, err := strconv.Atoi(mutexFractionEnv)
		if err != nil {
			return fmt.Errorf("failed to parse %s environment variable as int", profilingMutexRateEnvName)
		}
		pd.mutexRate = mutexProfileFraction
	}

	tokenFileEnv := os.Getenv(profilingTokenFileEnvName)
	if tokenFileEnv != "" {
		pd.tokenFile = tokenFileEnv
	}

	return nil
}

type tracingDiagnostics struct {
	enabled bool
	file    string
}

func newTracingDiagnostics(enabled bool, file string) *tracingDiagnostics {
	return &tracingDiagnostics{
		enabled: enabled,
		file:    file,
	}
}

func (td *tracingDiagnostics) overrideWithEnv() error {
	enabledEnv := os.Getenv(tracingEnabledEnvName)
	if enabledEnv != "" {
		enabled, err := strconv.ParseBool(enabledEnv)
		if err != nil {
			return fmt.Errorf("failed to parse %s environment variable as bool", tracingEnabledEnvName)
		}
		td.enabled = enabled
	}

	fileEnv := os.Getenv(tracingFileEnvName)
	if fileEnv != "" {
		td.file = fileEnv
	}

	return nil
}

func setupProfiling(d Diagnostics) error {
	profileDiagnostics := newProfilingDiagnostics(d.Profile, d.ProfileAddr, d.ProfilePort, d.ProfileBlockRate, d.ProfileMutexFraction)
	profileDiagnostics.tokenFile = d.ProfileTokenFile
	if err := profileDiagnostics.overrideWithEnv(); err != nil {
		return err
	}

	if !profileDiagnostics.enabled {
		return nil
	}

	operatorToken := profileDiagnostics.tokenFile != ""
	var token []byte
	var err error
	if operatorToken {
		token, err = readProfilingToken(profileDiagnostics.tokenFile)
	} else {
		token, err = generateProfilingToken()
	}
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(profileDiagnostics.addr, strconv.FormatUint(profileDiagnostics.port, 10))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("diagnostics: failed to listen for profiling on %s: %w", addr, err)
	}
	// The bound address is checked rather than the configured host, because an
	// empty host or a name can resolve to every interface or a routable address.
	if !operatorToken && !isLoopbackListener(ln) {
		_ = ln.Close()
		return fmt.Errorf("diagnostics: profiling address %s is not a loopback address; set -profile-token-file or %s to serve profiles on it", ln.Addr(), profilingTokenFileEnvName)
	}

	tokenFile := profileDiagnostics.tokenFile
	if !operatorToken {
		tokenFile, err = writeProfilingTokenFile(token)
		if err != nil {
			_ = ln.Close()
			return err
		}
	}

	fmt.Println("diagnostics: pprof profiling enabled", "addr", ln.Addr().String(), "tokenFile", tokenFile, "blockProfileRate", profileDiagnostics.blockRate, "mutexProfileRate", profileDiagnostics.mutexRate)
	runtime.SetBlockProfileRate(profileDiagnostics.blockRate)
	runtime.SetMutexProfileFraction(profileDiagnostics.mutexRate)

	srv := &http.Server{
		Handler:                      newProfilingHandler(token),
		DisableGeneralOptionsHandler: true,
		ReadHeaderTimeout:            profilingReadTimeout,
		ReadTimeout:                  profilingReadTimeout,
		WriteTimeout:                 profilingWriteTimeout,
		IdleTimeout:                  profilingIdleTimeout,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()
	return nil
}

func isLoopbackListener(ln net.Listener) bool {
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	return ok && tcpAddr.IP.IsLoopback()
}

func readProfilingToken(path string) ([]byte, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path comes from the operator's CLI flag or environment
	if err != nil {
		return nil, fmt.Errorf("diagnostics: failed to read profiling token file: %w", err)
	}
	token := bytes.TrimSpace(raw)
	if len(token) < profilingMinTokenLength {
		return nil, fmt.Errorf("diagnostics: profiling token in %s must be at least %d characters", path, profilingMinTokenLength)
	}
	return token, nil
}

func generateProfilingToken() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("diagnostics: failed to generate profiling token: %w", err)
	}
	return []byte(hex.EncodeToString(b)), nil
}

// writeProfilingTokenFile stores a generated token in a new file that only the
// Grafana user can read, so the token never appears in logs.
func writeProfilingTokenFile(token []byte) (string, error) {
	f, err := os.CreateTemp("", "grafana-profiling-token-*")
	if err != nil {
		return "", fmt.Errorf("diagnostics: failed to create profiling token file: %w", err)
	}
	if _, err := f.Write(token); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("diagnostics: failed to write profiling token file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("diagnostics: failed to write profiling token file: %w", err)
	}
	return f.Name(), nil
}

// newProfilingHandler serves only the profiling endpoints, never
// http.DefaultServeMux, and requires the token as a bearer token or as the
// basic-auth password so that go tool pprof can pass it in the URL.
func newProfilingHandler(token []byte) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	mux.HandleFunc("GET /debug/pprof/delta_heap", deltapprof.Heap)
	mux.HandleFunc("GET /debug/pprof/delta_block", deltapprof.Block)
	mux.HandleFunc("GET /debug/pprof/delta_mutex", deltapprof.Mutex)

	want := sha256.Sum256(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !profilingRequestAuthorized(r, want) {
			w.Header().Set("Connection", "close")
			w.Header().Set("WWW-Authenticate", `Basic realm="grafana-profiling"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func profilingRequestAuthorized(r *http.Request, want [sha256.Size]byte) bool {
	var presented string
	if _, password, ok := r.BasicAuth(); ok {
		presented = password
	} else if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		presented = bearer
	} else {
		return false
	}
	got := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

func setupTracing(tracing bool, tracingFile string, logger *log.ConcreteLogger) error {
	traceDiagnostics := newTracingDiagnostics(tracing, tracingFile)
	if err := traceDiagnostics.overrideWithEnv(); err != nil {
		return err
	}

	if traceDiagnostics.enabled {
		fmt.Println("diagnostics: tracing enabled", "file", traceDiagnostics.file)
		f, err := os.Create(traceDiagnostics.file)
		if err != nil {
			panic(err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				logger.Error("Failed to write trace diagnostics", "path", traceDiagnostics.file, "err", err)
			}
		}()

		if err := trace.Start(f); err != nil {
			panic(err)
		}
		defer trace.Stop()
	}
	return nil
}

// setupDiagnostics configures pprof profiling and execution tracing from the
// supplied Diagnostics, layering in any GF_DIAGNOSTICS_* environment overrides.
func setupDiagnostics(d Diagnostics, logger *log.ConcreteLogger) error {
	if err := setupProfiling(d); err != nil {
		return err
	}
	return setupTracing(d.Tracing, d.TracingFile, logger)
}
