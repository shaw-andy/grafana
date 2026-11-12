package idimpl

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/handlertest"
	"github.com/stretchr/testify/require"

	authnlib "github.com/grafana/authlib/authn"
	claims "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/remotecache"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/clientmiddleware"
	secretsdb "github.com/grafana/grafana/pkg/services/secrets/database"
	secretsmng "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/services/signingkeys/signingkeysimpl"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/proxyutil"
	"github.com/grafana/grafana/pkg/web"
)

// These tests describe the confidentiality of the signed identity token.
// They fail while SignIdentity writes that token into the shared cache as raw bytes.

func TestPostAuthHookDoesNotLeaveIdentityTokenRecoverableInDefaultDatabaseCache(t *testing.T) {
	ctx := context.Background()
	cfg := loadShippedConfig(t)
	store := sqlstore.NewTestStore(t)
	secretsSvc := secretsmng.SetupTestService(t, secretsdb.ProvideSecretsStore(store))
	cache, err := remotecache.ProvideService(cfg, store, &usagestats.UsageStatsMock{T: t}, secretsSvc)
	require.NoError(t, err)

	keys, err := signingkeysimpl.ProvideEmbeddedSigningKeysService(store, secretsSvc, cache, routing.ProvideRegister())
	require.NoError(t, err)
	signer, err := ProvideLocalSigner(keys)
	require.NoError(t, err)

	ident := testUserIdentity()
	var hook authn.PostAuthHookFn
	svc := ProvideService(cfg, signer, cache, &authntest.MockService{
		RegisterPostAuthHookFunc: func(fn authn.PostAuthHookFn, _ uint) {
			hook = fn
		},
	}, nil, tracing.InitializeTracerForTest())
	require.NotNil(t, hook, "post-auth hook was not registered")

	require.NoError(t, hook(ctx, ident, &authn.Request{}))
	token := ident.GetIDToken()
	requireVerifiableIdentityToken(t, ctx, keys, token, ident)
	requireForwardedDatasourceHeader(t, ident, token)
	requireProxiedDatasourceHeader(t, ident, token)

	cached, err := svc.cache.Get(ctx, svc.getCacheKey(ident))
	if err == nil && bytes.Equal(cached, []byte(token)) {
		rows := readCacheRows(t, ctx, store)
		if len(rows) == 0 {
			t.Fatal("cache served the signed identity token but cache_data had no rows")
		}
	}

	for _, row := range readCacheRows(t, ctx, store) {
		if identityTokenRecoverable(row.Data, token) {
			t.Fatalf("cache_data holds a recoverable signed identity token (key length %d, value length %d)", len(row.CacheKey), len(row.Data))
		}
	}
}

func TestSignIdentityDoesNotSendIdentityTokenInCleartextToRedisWithoutTLS(t *testing.T) {
	ctx := context.Background()
	wire, addr := startRedisSink(t)
	cfg := setting.NewCfg()
	cfg.AppURL = "http://localhost:3000/"
	cfg.RemoteCacheOptions = &setting.RemoteCacheSettings{
		Name:       "redis",
		ConnStr:    "addr=" + addr + ",ssl=false",
		Encryption: false,
	}

	token := signThroughRemoteCache(t, ctx, cfg)
	captured := wire()
	if bytes.Contains(captured, []byte(token)) {
		t.Fatalf("redis received the signed identity token in cleartext (%d bytes on the connection)", len(captured))
	}
}

func TestSignIdentityDoesNotSendIdentityTokenInCleartextToMemcached(t *testing.T) {
	ctx := context.Background()
	wire, addr := startMemcachedSink(t)
	cfg := setting.NewCfg()
	cfg.AppURL = "http://localhost:3000/"
	cfg.RemoteCacheOptions = &setting.RemoteCacheSettings{
		Name:       "memcached",
		ConnStr:    addr,
		Encryption: false,
	}

	token := signThroughRemoteCache(t, ctx, cfg)
	captured := wire()
	if bytes.Contains(captured, []byte(token)) {
		t.Fatalf("memcached received the signed identity token in cleartext (%d bytes on the connection)", len(captured))
	}
}

func signThroughRemoteCache(t *testing.T, ctx context.Context, cfg *setting.Cfg) string {
	t.Helper()

	store := sqlstore.NewTestStore(t)
	secretsSvc := secretsmng.SetupTestService(t, secretsdb.ProvideSecretsStore(store))
	cache, err := remotecache.ProvideService(cfg, store, &usagestats.UsageStatsMock{T: t}, secretsSvc)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := &ephemeralSigner{key: key}

	ident := testUserIdentity()
	svc := ProvideService(cfg, signer, cache, &authntest.FakeService{}, nil, tracing.InitializeTracerForTest())
	signed, _, err := svc.SignIdentity(ctx, ident)
	require.NoError(t, err)
	requireSignedBy(t, signed, &key.PublicKey, ident)
	return signed
}

func loadShippedConfig(t *testing.T) *setting.Cfg {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	cfg, err := setting.NewCfgFromArgs(setting.CommandLineArgs{HomePath: root})
	require.NoError(t, err)
	require.NotNil(t, cfg.RemoteCacheOptions)
	return cfg
}

func testUserIdentity() *authn.Identity {
	return &authn.Identity{
		ID:              "7",
		UID:             "user-7",
		Type:            claims.TypeUser,
		OrgID:           1,
		OrgRoles:        map[int64]org.RoleType{1: org.RoleAdmin},
		Login:           "ada",
		Name:            "Ada Lovelace",
		Email:           "ada@example.com",
		EmailVerified:   true,
		AuthenticatedBy: login.PasswordAuthModule,
		Groups:          []string{"team-a"},
	}
}

type storedCacheRow struct {
	CacheKey  string `xorm:"cache_key"`
	Data      []byte `xorm:"data"`
	Expires   int64  `xorm:"expires"`
	CreatedAt int64  `xorm:"created_at"`
}

func readCacheRows(t *testing.T, ctx context.Context, store *sqlstore.SQLStore) []storedCacheRow {
	t.Helper()
	var rows []storedCacheRow
	err := store.WithDbSession(ctx, func(sess *sqlstore.DBSession) error {
		return sess.SQL("SELECT cache_key, data, expires, created_at FROM cache_data").Find(&rows)
	})
	require.NoError(t, err)
	return rows
}

func identityTokenRecoverable(stored []byte, token string) bool {
	if token != "" && bytes.Contains(stored, []byte(token)) {
		return true
	}
	parsed, err := jwt.ParseSigned(string(stored), []jose.SignatureAlgorithm{jose.ES256})
	return err == nil && parsed != nil
}

func requireVerifiableIdentityToken(t *testing.T, ctx context.Context, keys *signingkeysimpl.Service, token string, ident *authn.Identity) {
	t.Helper()
	require.NotEmpty(t, token)
	jwks, err := keys.GetJWKS(ctx)
	require.NoError(t, err)
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	var pub any
	for _, header := range parsed.Headers {
		if matches := jwks.Key(header.KeyID); len(matches) > 0 {
			pub = matches[0]
			break
		}
	}
	require.NotNil(t, pub, "signing key for the identity token was not published")
	requireSignedClaims(t, parsed, pub, ident)
}

func requireSignedBy(t *testing.T, token string, pub any, ident *authn.Identity) {
	t.Helper()
	require.NotEmpty(t, token)
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	requireSignedClaims(t, parsed, pub, ident)
}

func requireSignedClaims(t *testing.T, parsed *jwt.JSONWebToken, key any, ident *authn.Identity) {
	t.Helper()
	var got authnlib.Claims[authnlib.IDTokenClaims]
	require.NoError(t, parsed.Claims(key, &got.Claims, &got.Rest))
	require.Equal(t, ident.Email, got.Rest.Email)
	require.Equal(t, ident.Login, got.Rest.Username)
	require.Equal(t, ident.Name, got.Rest.DisplayName)
	require.Equal(t, string(ident.GetOrgRole()), got.Rest.Role)
	require.Equal(t, ident.Groups, got.Rest.Groups)
	require.WithinDuration(t, time.Now().Add(tokenTTL), got.Expiry.Time(), time.Minute)
}

func requireForwardedDatasourceHeader(t *testing.T, ident *authn.Identity, token string) {
	t.Helper()
	cdt := handlertest.NewHandlerMiddlewareTest(t, handlertest.WithMiddlewares(clientmiddleware.NewForwardIDMiddleware()))
	ctx := context.WithValue(context.Background(), ctxkey.Key{}, &contextmodel.ReqContext{
		Context:      &web.Context{Req: &http.Request{}},
		SignedInUser: ident.SignedInUser(),
	})
	_, err := cdt.MiddlewareHandler.QueryData(ctx, &backend.QueryDataRequest{
		PluginContext: backend.PluginContext{DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{}},
	})
	require.NoError(t, err)
	header := cdt.QueryDataReq.GetHTTPHeader("X-Grafana-Id")
	if header == "" {
		t.Fatal("datasource query was not given an X-Grafana-Id header")
	}
	if header != token {
		t.Fatal("X-Grafana-Id was not the signed identity token")
	}
}

func requireProxiedDatasourceHeader(t *testing.T, ident identity.Requester, token string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://datasource.example/query", nil)
	require.NoError(t, err)
	proxyutil.ApplyForwardIDHeader(req, ident)
	header := req.Header.Get(proxyutil.IDHeaderName)
	if header == "" {
		t.Fatal("datasource proxy request was not given an X-Grafana-Id header")
	}
	if header != token {
		t.Fatal("proxied X-Grafana-Id was not the signed identity token")
	}
}

type ephemeralSigner struct {
	key *ecdsa.PrivateKey
}

func (s *ephemeralSigner) SignIDToken(_ context.Context, idClaims *auth.IDClaims) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: s.key}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			jose.HeaderKey("kid"): "ephemeral",
			jose.HeaderType:       "jwt",
		},
	})
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(&idClaims.Rest).Claims(idClaims.Claims).Serialize()
}

func startRedisSink(t *testing.T) (func() []byte, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var captured bytes.Buffer
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				reader := bufio.NewReader(c)
				for {
					cmd, raw, err := readRESPCommand(reader)
					mu.Lock()
					captured.Write(raw)
					mu.Unlock()
					if err != nil {
						return
					}
					name := ""
					if len(cmd) > 0 {
						name = strings.ToUpper(string(cmd[0]))
					}
					switch name {
					case "HELLO":
						// A Redis error makes go-redis fall back to RESP2 and continue on this connection.
						_, _ = c.Write([]byte("-ERR unknown command\r\n"))
					case "GET":
						_, _ = c.Write([]byte("$-1\r\n"))
					default:
						_, _ = c.Write([]byte("+OK\r\n"))
					}
				}
			}(conn)
		}
	}()

	return func() []byte {
		mu.Lock()
		defer mu.Unlock()
		return append([]byte(nil), captured.Bytes()...)
	}, ln.Addr().String()
}

func startMemcachedSink(t *testing.T) (func() []byte, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var captured bytes.Buffer
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				reader := bufio.NewReader(c)
				for {
					header, err := reader.ReadSlice('\n')
					mu.Lock()
					captured.Write(header)
					mu.Unlock()
					if err != nil {
						return
					}
					fields := strings.Fields(string(header))
					if len(fields) >= 5 && strings.EqualFold(fields[0], "set") {
						n, convErr := strconv.Atoi(fields[4])
						if convErr != nil {
							return
						}
						body := make([]byte, n+2)
						if _, err := io.ReadFull(reader, body); err != nil {
							return
						}
						mu.Lock()
						captured.Write(body)
						mu.Unlock()
					}
					_, _ = c.Write([]byte("STORED\r\n"))
				}
			}(conn)
		}
	}()

	return func() []byte {
		mu.Lock()
		defer mu.Unlock()
		return append([]byte(nil), captured.Bytes()...)
	}, ln.Addr().String()
}

func readRESPCommand(r *bufio.Reader) ([][]byte, []byte, error) {
	var raw bytes.Buffer
	line, err := r.ReadSlice('\n')
	raw.Write(line)
	if err != nil {
		return nil, raw.Bytes(), err
	}
	if len(line) == 0 || line[0] != '*' {
		return nil, raw.Bytes(), io.ErrUnexpectedEOF
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(line[1:])))
	if err != nil || n < 0 {
		return nil, raw.Bytes(), io.ErrUnexpectedEOF
	}
	parts := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := r.ReadSlice('\n')
		raw.Write(hdr)
		if err != nil {
			return parts, raw.Bytes(), err
		}
		if len(hdr) == 0 || hdr[0] != '$' {
			return parts, raw.Bytes(), io.ErrUnexpectedEOF
		}
		size, err := strconv.Atoi(strings.TrimSpace(string(hdr[1:])))
		if err != nil || size < 0 {
			return parts, raw.Bytes(), io.ErrUnexpectedEOF
		}
		bulk := make([]byte, size+2)
		if _, err := io.ReadFull(r, bulk); err != nil {
			raw.Write(bulk)
			return parts, raw.Bytes(), err
		}
		raw.Write(bulk)
		parts = append(parts, append([]byte(nil), bulk[:size]...))
	}
	return parts, raw.Bytes(), nil
}
