package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	authnlib "github.com/grafana/authlib/authn"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/grpcutils"
	"github.com/grafana/authlib/types"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/infra/leaderelection"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	authzextv1 "github.com/grafana/grafana/pkg/services/authz/proto/v1"
	"github.com/grafana/grafana/pkg/services/authz/zanzana"
	"github.com/grafana/grafana/pkg/services/authz/zanzana/common"
	zStore "github.com/grafana/grafana/pkg/services/authz/zanzana/store"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/sqlstore/migrator"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/testutil"
)

const (
	// authzServiceAudience is the audience the standalone server passes to its
	// access-token verifier. Defined in pkg/services/authz/rbac.go.
	authzServiceAudience = "authzService"

	tokenNamespace  = "org-2"
	victimNamespace = "org-3"

	victimSubject          = "user:victim-reader"
	victimFolder           = "victim-child"
	victimParent           = "victim-parent-uid"
	callerFolder           = "caller-child"
	callerParent           = "caller-parent"
	crossTenantWriteObject = "cross-tenant-write"
)

func TestIntegrationAllowInsecureKeepsNamespaceIsolationInProduction(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	keys := newTestSigningKeys(t)
	updateCtx := keys.authenticate(t, tokenNamespace, []string{zanzana.TokenPermissionUpdate})
	readCtx := keys.authenticate(t, tokenNamespace, nil)

	victimParentTuple := common.NewFolderParentTuple(victimFolder, victimParent)
	victimGrant := common.NewGroupResourceTuple(victimSubject, common.RelationGet, dashboardGroup, dashboardResource, "")
	callerParentTuple := common.NewFolderParentTuple(callerFolder, callerParent)
	crossTenantTuple := &openfgav1.TupleKey{
		User:     common.NewFolderIdent(callerParent),
		Relation: common.RelationParent,
		Object:   common.NewFolderIdent(crossTenantWriteObject),
	}

	prod := newStandaloneServer(t, setting.Prod, true)
	seedNamespace(t, prod, victimNamespace, []*openfgav1.TupleKey{victimParentTuple, victimGrant})
	seedNamespace(t, prod, tokenNamespace, []*openfgav1.TupleKey{callerParentTuple})

	t.Run("read of another namespace is denied and both stores stay unchanged", func(t *testing.T) {
		beforeVictim := tupleIDs(t, prod, victimNamespace)
		beforeCaller := tupleIDs(t, prod, tokenNamespace)
		require.Contains(t, beforeVictim, tupleID(victimParentTuple))

		res, err := prod.Read(updateCtx, &authzextv1.ReadRequest{Namespace: victimNamespace})
		if err == nil {
			t.Errorf("read returned tuples from %s: %v", victimNamespace, extTupleIDs(res))
		}
		requireNamespaceDenied(t, err, "failed to perform read request")
		require.Nil(t, res)
		require.Equal(t, beforeVictim, tupleIDs(t, prod, victimNamespace))
		require.Equal(t, beforeCaller, tupleIDs(t, prod, tokenNamespace))
	})

	t.Run("check of another namespace is denied", func(t *testing.T) {
		beforeVictim := tupleIDs(t, prod, victimNamespace)
		res, err := prod.Check(updateCtx, &authzv1.CheckRequest{
			Namespace: victimNamespace,
			Subject:   victimSubject,
			Verb:      utils.VerbGet,
			Group:     dashboardGroup,
			Resource:  dashboardResource,
			Name:      "victim-dashboard",
		})
		if err == nil {
			t.Errorf("check allowed=%t for subject %s in %s", res.GetAllowed(), victimSubject, victimNamespace)
		}
		requireNamespaceDenied(t, err, "failed to perform check request")
		require.Nil(t, res)
		require.Equal(t, beforeVictim, tupleIDs(t, prod, victimNamespace))
	})

	t.Run("batch check of another namespace is denied", func(t *testing.T) {
		beforeVictim := tupleIDs(t, prod, victimNamespace)
		res, err := prod.BatchCheck(updateCtx, &authzv1.BatchCheckRequest{
			Namespace: victimNamespace,
			Subject:   victimSubject,
			Checks: []*authzv1.BatchCheckItem{{
				CorrelationId: "victim",
				Verb:          utils.VerbGet,
				Group:         dashboardGroup,
				Resource:      dashboardResource,
				Name:          "victim-dashboard",
			}},
		})
		if err == nil {
			t.Errorf("batch check result=%v for %s", res.GetResults(), victimNamespace)
		}
		requireNamespaceDenied(t, err, "failed to perform batch check request")
		require.Nil(t, res)
		require.Equal(t, beforeVictim, tupleIDs(t, prod, victimNamespace))
	})

	t.Run("list of another namespace is denied", func(t *testing.T) {
		beforeVictim := tupleIDs(t, prod, victimNamespace)
		res, err := prod.List(updateCtx, &authzv1.ListRequest{
			Namespace: victimNamespace,
			Subject:   victimSubject,
			Verb:      utils.VerbList,
			Group:     dashboardGroup,
			Resource:  dashboardResource,
		})
		if err == nil {
			t.Errorf("list all=%t items=%v folders=%v for %s", res.GetAll(), res.GetItems(), res.GetFolders(), victimNamespace)
		}
		requireNamespaceDenied(t, err, "failed to perform list request")
		require.Nil(t, res)
		require.Equal(t, beforeVictim, tupleIDs(t, prod, victimNamespace))
	})

	t.Run("query of another namespace is denied", func(t *testing.T) {
		beforeVictim := tupleIDs(t, prod, victimNamespace)
		res, err := prod.Query(updateCtx, &authzextv1.QueryRequest{
			Namespace: victimNamespace,
			Operation: &authzextv1.QueryOperation{
				Operation: &authzextv1.QueryOperation_GetFolderParents{
					GetFolderParents: &authzextv1.GetFolderParentsQuery{Folder: victimFolder},
				},
			},
		})
		if err == nil {
			t.Errorf("query parents=%v for folder %s in %s", res.GetFolderParents().GetParentUids(), victimFolder, victimNamespace)
		}
		requireNamespaceDenied(t, err, "failed to perform query request")
		require.Nil(t, res)
		require.Equal(t, beforeVictim, tupleIDs(t, prod, victimNamespace))
	})

	t.Run("write into another namespace is denied and the tuple is not stored", func(t *testing.T) {
		beforeVictim := tupleIDs(t, prod, victimNamespace)
		beforeCaller := tupleIDs(t, prod, tokenNamespace)
		res, err := prod.Write(updateCtx, &authzextv1.WriteRequest{
			Namespace: victimNamespace,
			Writes: &authzextv1.WriteRequestWrites{
				TupleKeys: []*authzextv1.TupleKey{toExtTupleKey(crossTenantTuple)},
			},
		})
		if err == nil {
			t.Errorf("write accepted; victim tuples=%v caller tuples=%v", tupleIDs(t, prod, victimNamespace), tupleIDs(t, prod, tokenNamespace))
		}
		requireNamespaceDenied(t, err, "failed to perform write request")
		require.Nil(t, res)
		require.NotContains(t, tupleIDs(t, prod, victimNamespace), tupleID(crossTenantTuple))
		require.NotContains(t, tupleIDs(t, prod, tokenNamespace), tupleID(crossTenantTuple))
		require.Equal(t, beforeVictim, tupleIDs(t, prod, victimNamespace))
		require.Equal(t, beforeCaller, tupleIDs(t, prod, tokenNamespace))
	})

	t.Run("write cannot delete another namespace's tuple", func(t *testing.T) {
		beforeVictim := tupleIDs(t, prod, victimNamespace)
		res, err := prod.Write(updateCtx, &authzextv1.WriteRequest{
			Namespace: victimNamespace,
			Deletes: &authzextv1.WriteRequestDeletes{
				TupleKeys: []*authzextv1.TupleKeyWithoutCondition{{
					User:     victimParentTuple.GetUser(),
					Relation: victimParentTuple.GetRelation(),
					Object:   victimParentTuple.GetObject(),
				}},
			},
		})
		if err == nil {
			t.Errorf("delete accepted; victim tuples=%v", tupleIDs(t, prod, victimNamespace))
		}
		requireNamespaceDenied(t, err, "failed to perform write request")
		require.Nil(t, res)
		require.Equal(t, beforeVictim, tupleIDs(t, prod, victimNamespace))
		require.Contains(t, tupleIDs(t, prod, victimNamespace), tupleID(victimParentTuple))
	})

	t.Run("mutate of another namespace is denied and the tuple is not stored", func(t *testing.T) {
		beforeVictim := tupleIDs(t, prod, victimNamespace)
		beforeCaller := tupleIDs(t, prod, tokenNamespace)
		res, err := prod.Mutate(updateCtx, &authzextv1.MutateRequest{
			Namespace: victimNamespace,
			Operations: []*authzextv1.MutateOperation{{
				Operation: &authzextv1.MutateOperation_SetFolderParent{
					SetFolderParent: &authzextv1.SetFolderParentOperation{
						Folder: crossTenantWriteObject,
						Parent: callerParent,
					},
				},
			}},
		})
		if err == nil {
			t.Errorf("mutate accepted; victim tuples=%v caller tuples=%v", tupleIDs(t, prod, victimNamespace), tupleIDs(t, prod, tokenNamespace))
		}
		requireNamespaceDenied(t, err, "failed to perform mutate request")
		require.Nil(t, res)
		require.NotContains(t, tupleIDs(t, prod, victimNamespace), tupleID(crossTenantTuple))
		require.NotContains(t, tupleIDs(t, prod, tokenNamespace), tupleID(crossTenantTuple))
		require.Equal(t, beforeVictim, tupleIDs(t, prod, victimNamespace))
		require.Equal(t, beforeCaller, tupleIDs(t, prod, tokenNamespace))
	})

	t.Run("mutate cannot delete another namespace's folder parent", func(t *testing.T) {
		beforeVictim := tupleIDs(t, prod, victimNamespace)
		res, err := prod.Mutate(updateCtx, &authzextv1.MutateRequest{
			Namespace: victimNamespace,
			Operations: []*authzextv1.MutateOperation{{
				Operation: &authzextv1.MutateOperation_DeleteFolder{
					DeleteFolder: &authzextv1.DeleteFolderOperation{
						Folder: victimFolder,
						Parent: victimParent,
					},
				},
			}},
		})
		if err == nil {
			t.Errorf("folder delete accepted; victim tuples=%v", tupleIDs(t, prod, victimNamespace))
		}
		requireNamespaceDenied(t, err, "failed to perform mutate request")
		require.Nil(t, res)
		require.Equal(t, beforeVictim, tupleIDs(t, prod, victimNamespace))
		require.Contains(t, tupleIDs(t, prod, victimNamespace), tupleID(victimParentTuple))
	})

	t.Run("matching namespace can still be read", func(t *testing.T) {
		res, err := prod.Read(updateCtx, &authzextv1.ReadRequest{Namespace: tokenNamespace})
		require.NoError(t, err)
		require.Contains(t, extTupleIDs(res), tupleID(callerParentTuple))
	})

	t.Run("update permission is still required for a write in the token namespace", func(t *testing.T) {
		beforeCaller := tupleIDs(t, prod, tokenNamespace)
		res, err := prod.Write(readCtx, &authzextv1.WriteRequest{
			Namespace: tokenNamespace,
			Writes: &authzextv1.WriteRequestWrites{
				TupleKeys: []*authzextv1.TupleKey{toExtTupleKey(crossTenantTuple)},
			},
		})
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		require.Nil(t, res)
		require.Equal(t, beforeCaller, tupleIDs(t, prod, tokenNamespace))
	})

	t.Run("development with allow_insecure still reads and writes the requested namespace", func(t *testing.T) {
		dev := newStandaloneServer(t, setting.Dev, true)
		seedNamespace(t, dev, victimNamespace, []*openfgav1.TupleKey{victimParentTuple, victimGrant})
		seedNamespace(t, dev, tokenNamespace, []*openfgav1.TupleKey{callerParentTuple})

		readRes, err := dev.Read(updateCtx, &authzextv1.ReadRequest{Namespace: victimNamespace})
		require.NoError(t, err)
		require.Contains(t, extTupleIDs(readRes), tupleID(victimParentTuple))

		checkRes, err := dev.Check(updateCtx, &authzv1.CheckRequest{
			Namespace: victimNamespace,
			Subject:   victimSubject,
			Verb:      utils.VerbGet,
			Group:     dashboardGroup,
			Resource:  dashboardResource,
			Name:      "victim-dashboard",
		})
		require.NoError(t, err)
		require.True(t, checkRes.GetAllowed())

		_, err = dev.Write(updateCtx, &authzextv1.WriteRequest{
			Namespace: victimNamespace,
			Writes: &authzextv1.WriteRequestWrites{
				TupleKeys: []*authzextv1.TupleKey{toExtTupleKey(crossTenantTuple)},
			},
		})
		require.NoError(t, err)
		require.Contains(t, tupleIDs(t, dev, victimNamespace), tupleID(crossTenantTuple))
		require.NotContains(t, tupleIDs(t, dev, tokenNamespace), tupleID(crossTenantTuple))
	})

	t.Run("production without allow_insecure denies another namespace", func(t *testing.T) {
		locked := newStandaloneServer(t, setting.Prod, false)
		seedNamespace(t, locked, victimNamespace, []*openfgav1.TupleKey{victimParentTuple})
		seedNamespace(t, locked, tokenNamespace, []*openfgav1.TupleKey{callerParentTuple})

		res, err := locked.Read(updateCtx, &authzextv1.ReadRequest{Namespace: victimNamespace})
		requireNamespaceDenied(t, err, "failed to perform read request")
		require.Nil(t, res)

		own, err := locked.Read(updateCtx, &authzextv1.ReadRequest{Namespace: tokenNamespace})
		require.NoError(t, err)
		require.Contains(t, extTupleIDs(own), tupleID(callerParentTuple))
	})

	t.Run("production authenticator rejects a call with no access token", func(t *testing.T) {
		_, err := keys.interceptor(metadata.NewIncomingContext(context.Background(), metadata.MD{}))
		require.Error(t, err)
		require.Equal(t, codes.Unauthenticated, status.Code(err))
	})
}

func requireNamespaceDenied(t *testing.T, err error, wrapped string) {
	t.Helper()
	require.Error(t, err)
	if status.Code(err) == codes.PermissionDenied {
		return
	}
	require.EqualError(t, err, wrapped)
}

func newStandaloneServer(t *testing.T, env string, allowInsecure bool) *Server {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.Env = env
	cfg.ZanzanaServer.AllowInsecure = allowInsecure

	testStore := sqlstore.NewTestStore(t, sqlstore.WithCfg(cfg))
	if testStore.GetDialect().DriverName() == migrator.MySQL {
		if supported, err := testStore.RecursiveQueriesAreSupported(); !supported || err != nil {
			t.Skip("skipping integration test")
		}
	}

	store, err := zStore.NewEmbeddedStore(cfg, testStore, log.NewNopLogger())
	require.NoError(t, err)

	srv, err := NewZanzanaServer(cfg, store, log.NewNopLogger(), tracing.NewNoopTracerService(), prometheus.NewRegistry(), nil, leaderelection.NewDefaultElector(), nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		srv.Close()
	})
	return srv
}

func seedNamespace(t *testing.T, srv *Server, namespace string, tuples []*openfgav1.TupleKey) {
	t.Helper()

	info, err := srv.getStoreInfo(context.Background(), namespace)
	require.NoError(t, err)
	if len(tuples) == 0 {
		return
	}

	_, err = srv.openFGAClient.Write(context.Background(), &openfgav1.WriteRequest{
		StoreId:              info.ID,
		AuthorizationModelId: info.ModelID,
		Writes: &openfgav1.WriteRequestWrites{
			TupleKeys:   tuples,
			OnDuplicate: "ignore",
		},
	})
	require.NoError(t, err)
}

func tupleIDs(t *testing.T, srv *Server, namespace string) []string {
	t.Helper()

	info, err := srv.getStoreInfo(context.Background(), namespace)
	require.NoError(t, err)
	res, err := srv.ReadTuples(context.Background(), info, &openfgav1.ReadRequest{})
	require.NoError(t, err)

	ids := make([]string, 0, len(res.GetTuples()))
	for _, tuple := range res.GetTuples() {
		ids = append(ids, tupleID(tuple.GetKey()))
	}
	sort.Strings(ids)
	return ids
}

func tupleID(key *openfgav1.TupleKey) string {
	return key.GetUser() + "#" + key.GetRelation() + "@" + key.GetObject()
}

func extTupleIDs(res *authzextv1.ReadResponse) []string {
	ids := make([]string, 0, len(res.GetTuples()))
	for _, tuple := range res.GetTuples() {
		key := tuple.GetKey()
		ids = append(ids, key.GetUser()+"#"+key.GetRelation()+"@"+key.GetObject())
	}
	return ids
}

func toExtTupleKey(key *openfgav1.TupleKey) *authzextv1.TupleKey {
	return &authzextv1.TupleKey{
		User:     key.GetUser(),
		Relation: key.GetRelation(),
		Object:   key.GetObject(),
	}
}

type grpcutilsAuthenticator func(context.Context) (context.Context, error)

type testSigningKeys struct {
	interceptor grpcutilsAuthenticator
	sign        func(namespace string, permissions []string) string
}

func newTestSigningKeys(t *testing.T) testSigningKeys {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	const keyID = "zanzana-test-key"
	publicKey := jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     keyID,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicKey}}))
	}))
	t.Cleanup(jwks.Close)

	authenticator := authnlib.NewAccessTokenAuthenticator(
		authnlib.NewAccessTokenVerifier(
			authnlib.VerifierConfig{AllowedAudiences: []string{authzServiceAudience}},
			authnlib.NewKeyRetriever(authnlib.KeyRetrieverConfig{SigningKeysURL: jwks.URL}),
		),
	)
	interceptor := grpcutils.NewAuthenticatorInterceptor(authenticator, noop.NewTracerProvider().Tracer("zanzana-test"))

	return testSigningKeys{
		interceptor: interceptor,
		sign: func(namespace string, permissions []string) string {
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.ES256,
				Key: jose.JSONWebKey{
					Key:       privateKey,
					KeyID:     keyID,
					Algorithm: string(jose.ES256),
					Use:       "sig",
				},
			}, &jose.SignerOptions{
				ExtraHeaders: map[jose.HeaderKey]any{
					"typ": authnlib.TokenTypeAccess,
				},
			})
			require.NoError(t, err)

			token, err := jwt.Signed(signer).Claims(authnlib.AccessTokenClaims{
				Namespace:   namespace,
				Permissions: permissions,
			}).Claims(jwt.Claims{
				Subject:  "access-policy:" + namespace,
				Audience: jwt.Audience{authzServiceAudience},
				Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			}).Serialize()
			require.NoError(t, err)
			return token
		},
	}
}

func (k testSigningKeys) authenticate(t *testing.T, namespace string, permissions []string) context.Context {
	t.Helper()

	// The header name is the one GRPCTokenProvider reads. The constant is unexported.
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("X-Access-Token", k.sign(namespace, permissions)))
	authed, err := k.interceptor(ctx)
	require.NoError(t, err)

	info, ok := types.AuthInfoFrom(authed)
	require.True(t, ok)
	require.Equal(t, namespace, info.GetNamespace())
	require.Equal(t, permissions, info.GetTokenPermissions())
	return authed
}
