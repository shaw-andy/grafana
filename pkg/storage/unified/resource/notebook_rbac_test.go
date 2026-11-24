package resource

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	authnlib "github.com/grafana/authlib/authn"
	authlib "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

// notebookPermissionClient is the permission service standing behind the limited
// authorization client. It allows a seeder to write fixtures, and allows the
// caller under test to update or delete only the notebook named in the check.
// A create is refused. A check for any other group, resource, namespace, or
// name is refused, so authorizing one notebook cannot mutate another.
type notebookPermissionClient struct {
	mu       sync.Mutex
	checks   []authlib.CheckRequest
	allowed  string
	ns       string
	seederID string
}

func (c *notebookPermissionClient) Check(_ context.Context, id authlib.AuthInfo, req authlib.CheckRequest, _ string) (authlib.CheckResponse, error) {
	c.mu.Lock()
	c.checks = append(c.checks, req)
	c.mu.Unlock()

	if id.GetUID() == c.seederID {
		return authlib.CheckResponse{Allowed: true}, nil
	}
	if req.Group != "dashboard.grafana.app" || req.Resource != "notebooks" || req.Namespace != c.ns {
		return authlib.CheckResponse{Allowed: false}, nil
	}
	switch req.Verb {
	case utils.VerbUpdate, utils.VerbPatch, utils.VerbDelete:
		return authlib.CheckResponse{Allowed: req.Name == c.allowed}, nil
	default:
		return authlib.CheckResponse{Allowed: false}, nil
	}
}

func (c *notebookPermissionClient) Compile(context.Context, authlib.AuthInfo, authlib.ListRequest) (authlib.ItemChecker, authlib.Zookie, error) {
	return func(string, string) bool { return false }, authlib.NoopZookie{}, nil
}

func (c *notebookPermissionClient) BatchCheck(_ context.Context, _ authlib.AuthInfo, req authlib.BatchCheckRequest) (authlib.BatchCheckResponse, error) {
	results := make(map[string]authlib.BatchCheckResult, len(req.Checks))
	for _, item := range req.Checks {
		results[item.CorrelationID] = authlib.BatchCheckResult{Allowed: false}
	}
	return authlib.BatchCheckResponse{Results: results}, nil
}

func (c *notebookPermissionClient) since(n int) []authlib.CheckRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]authlib.CheckRequest, len(c.checks)-n)
	copy(out, c.checks[n:])
	return out
}

func (c *notebookPermissionClient) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.checks)
}

// TestNotebookStorageWriteChecksTheSameNotebook proves that a notebook create,
// update, or delete is refused when the permission service refuses it, and that
// the check names the notebook being written. The limited client wraps the
// permission service with enforcement disabled for everything outside
// rbacAllowlist, which is how unified storage is constructed
// (sql.withAccessClient, authz_exemption_enabled defaulting off).
func TestNotebookStorageWriteChecksTheSameNotebook(t *testing.T) {
	const (
		group     = "dashboard.grafana.app"
		resource  = "notebooks"
		ns        = "default"
		keptName  = "kept"
		victim    = "victim"
		seederUID = "seeder"
	)

	perms := &notebookPermissionClient{
		allowed: keptName, ns: ns, seederID: authlib.NewTypeID(authlib.TypeAccessPolicy, seederUID),
	}
	// ExemptionEnabled false is the shipped default: only rbacAllowlist is enforced.
	access := NewAuthzLimitedClient(perms, AuthzOptions{Registry: prometheus.NewRegistry()})
	srv, _, seedCtx := newRecordingTestServer(t, access, "*")

	seeder := &identity.StaticRequester{
		Type: authlib.TypeAccessPolicy, Name: "seeder", UserUID: seederUID,
		Namespace: "*", OrgRole: identity.RoleAdmin,
	}
	// A signed-in user carries the service's delegated group permission, the
	// same grant AccessClaimsHook installs for a session that has no access token.
	caller := &identity.StaticRequester{
		Type: authlib.TypeUser, Name: "viewer", UserUID: "viewer", UserID: 7,
		Namespace: ns, OrgID: 1, OrgRole: identity.RoleViewer,
		AccessTokenClaims: &authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{
				DelegatedPermissions: []string{"dashboard.grafana.app:*"},
			},
		},
	}
	seedCtx = authlib.WithAuthInfo(context.Background(), seeder)
	callerCtx := authlib.WithAuthInfo(context.Background(), caller)

	keptRV := writeNotebook(t, srv, seedCtx, ns, keptName, "kept original")
	victimRV := writeNotebook(t, srv, seedCtx, ns, victim, "victim original")
	const deleteName = "delete-victim"
	deleteRV := writeNotebook(t, srv, seedCtx, ns, deleteName, "delete original")

	t.Run("update of a notebook the permission service did not allow does not change it", func(t *testing.T) {
		before := perms.len()
		rsp, err := srv.Update(callerCtx, &resourcepb.UpdateRequest{
			Key:             notebookKey(ns, victim),
			ResourceVersion: victimRV,
			Value:           notebookBody(t, ns, victim, "tampered"),
		})
		require.NoError(t, err)
		checks := perms.since(before)
		require.NotNilf(t, rsp.Error, "update of %s was stored without a matching permission check (%d checks)", victim, len(checks))
		require.Equal(t, int32(http.StatusForbidden), rsp.Error.Code)
		require.Equal(t, "victim original", readNotebookTitle(t, srv, seedCtx, ns, victim))
		requireNotebookChecks(t, checks, group, resource, ns, victim, utils.VerbUpdate)
	})

	t.Run("update is stored only when the check names that notebook", func(t *testing.T) {
		before := perms.len()
		rsp, err := srv.Update(callerCtx, &resourcepb.UpdateRequest{
			Key:             notebookKey(ns, keptName),
			ResourceVersion: keptRV,
			Value:           notebookBody(t, ns, keptName, "kept edited"),
		})
		require.NoError(t, err)
		checks := perms.since(before)
		require.Nil(t, rsp.Error)
		require.Equal(t, "kept edited", readNotebookTitle(t, srv, seedCtx, ns, keptName))
		requireNotebookChecks(t, checks, group, resource, ns, keptName, utils.VerbUpdate)
	})

	t.Run("delete of a notebook the permission service did not allow leaves it in place", func(t *testing.T) {
		before := perms.len()
		rsp, err := srv.Delete(callerCtx, &resourcepb.DeleteRequest{
			Key:             notebookKey(ns, deleteName),
			ResourceVersion: deleteRV,
		})
		require.NoError(t, err)
		checks := perms.since(before)
		require.NotNilf(t, rsp.Error, "delete of %s was stored without a matching permission check (%d checks)", deleteName, len(checks))
		require.Equal(t, int32(http.StatusForbidden), rsp.Error.Code)
		require.Equal(t, "delete original", readNotebookTitle(t, srv, seedCtx, ns, deleteName))
		requireNotebookChecks(t, checks, group, resource, ns, deleteName, utils.VerbDelete)
	})

	t.Run("create the permission service refused does not persist", func(t *testing.T) {
		const name = "extra"
		before := perms.len()
		rsp, err := srv.Create(callerCtx, &resourcepb.CreateRequest{
			Key:   notebookKey(ns, name),
			Value: notebookBody(t, ns, name, "should not exist"),
		})
		require.NoError(t, err)
		checks := perms.since(before)
		require.NotNilf(t, rsp.Error, "create of %s was stored without a matching permission check (%d checks)", name, len(checks))
		require.Equal(t, int32(http.StatusForbidden), rsp.Error.Code)
		require.Equal(t, int32(http.StatusNotFound), readNotebook(t, srv, seedCtx, ns, name).Error.Code)
		require.NotEmpty(t, checks)
		for _, check := range checks {
			require.Equal(t, group, check.Group)
			require.Equal(t, resource, check.Resource)
			require.Equal(t, ns, check.Namespace)
			require.Equal(t, utils.VerbCreate, check.Verb)
			// Create checks may omit the name. They must not name some other notebook.
			require.Contains(t, []string{"", name}, check.Name)
		}
	})
}

func requireNotebookChecks(t *testing.T, checks []authlib.CheckRequest, group, resource, ns, name, verb string) {
	t.Helper()
	require.NotEmpty(t, checks, "no permission check was made for %s %s", verb, name)
	for _, check := range checks {
		require.Equal(t, group, check.Group)
		require.Equal(t, resource, check.Resource)
		require.Equal(t, ns, check.Namespace)
		require.Equal(t, name, check.Name, "permission check named %q while the write targeted %q", check.Name, name)
		require.Equal(t, verb, check.Verb)
	}
}

func notebookKey(ns, name string) *resourcepb.ResourceKey {
	return &resourcepb.ResourceKey{
		Group: "dashboard.grafana.app", Resource: "notebooks", Namespace: ns, Name: name,
	}
}

func notebookBody(t *testing.T, ns, name, title string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "dashboard.grafana.app/v2beta1",
		"kind":       "Notebook",
		"metadata":   map[string]any{"name": name, "namespace": ns},
		"spec":       map[string]any{"title": title},
	})
	require.NoError(t, err)
	return raw
}

func writeNotebook(t *testing.T, srv *server, ctx context.Context, ns, name, title string) int64 {
	t.Helper()
	created, err := srv.Create(ctx, &resourcepb.CreateRequest{
		Key:   notebookKey(ns, name),
		Value: notebookBody(t, ns, name, title),
	})
	require.NoError(t, err)
	require.Nil(t, created.Error)
	return created.ResourceVersion
}

func readNotebook(t *testing.T, srv *server, ctx context.Context, ns, name string) *resourcepb.ReadResponse {
	t.Helper()
	rsp, err := srv.Read(ctx, &resourcepb.ReadRequest{Key: notebookKey(ns, name)})
	require.NoError(t, err)
	require.NotNil(t, rsp)
	return rsp
}

func readNotebookTitle(t *testing.T, srv *server, ctx context.Context, ns, name string) string {
	t.Helper()
	rsp := readNotebook(t, srv, ctx, ns, name)
	require.Nil(t, rsp.Error)
	var obj map[string]any
	require.NoError(t, json.Unmarshal(rsp.Value, &obj))
	spec, _ := obj["spec"].(map[string]any)
	title, _ := spec["title"].(string)
	return title
}
