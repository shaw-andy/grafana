package datasource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	claims "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	datasourceV0 "github.com/grafana/grafana/pkg/apis/datasource/v0alpha1"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/registry/apis/datasource/converter"
	"github.com/grafana/grafana/pkg/services/apiserver/auth/authenticator"
	gfauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/apiserver/endpoints/request"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/org"
)

const systemMastersGroup = "system:masters"

// TestSystemMastersGroupDoesNotListOrCreateAnotherOrgsDatasources is the
// datasource half of the privileged-group bypass. The authorizer runs first,
// the way the apiserver handler chain does, and the legacy datasource store
// runs only when that decision is allow. The store takes the organization from
// the URL namespace.
func TestSystemMastersGroupDoesNotListOrCreateAnotherOrgsDatasources(t *testing.T) {
	id := &authn.Identity{
		ID:        "7",
		UID:       "user-7",
		Type:      claims.TypeUser,
		OrgID:     2,
		Namespace: "org-2",
		Login:     "org-two-admin",
		Name:      "Org Two Admin",
		OrgRoles:  map[int64]org.RoleType{2: org.RoleAdmin},
		// Populated the same way user sync copies team UIDs into Groups.
		Groups: []string{systemMastersGroup},
	}
	ctx := identity.WithRequester(context.Background(), id)
	ctx = genericapirequest.WithNamespace(ctx, "default")

	rec := &recordingDataSources{}
	provider := &scopedDatasourceProvider{
		plugin:    plugins.JSONData{ID: "prometheus"},
		dsService: rec,
		converter: converter.NewConverter(request.GetNamespaceMapper(nil), "prometheus.datasource.grafana.app", "prometheus", nil),
	}

	listDecision := authorizeDatasource(t, ctx, id, "list", "")
	var listed *datasourceV0.DataSourceList
	if listDecision == authorizer.DecisionAllow {
		var err error
		listed, err = provider.ListDataSources(ctx)
		require.NoError(t, err)
	}
	require.Equal(t, authorizer.DecisionDeny, listDecision)
	require.Empty(t, rec.listedOrgs)
	require.Nil(t, listed)

	createDecision := authorizeDatasource(t, ctx, id, "create", "")
	body := &datasourceV0.DataSource{ObjectMeta: metav1.ObjectMeta{Name: "planted", Namespace: "default"}}
	body.Spec.SetTitle("planted").SetURL("http://org-one.example").SetUser("org-one-user")
	if createDecision == authorizer.DecisionAllow {
		_, err := provider.CreateDataSource(ctx, body)
		require.NoError(t, err)
	}
	require.Equal(t, authorizer.DecisionDeny, createDecision)
	require.Empty(t, rec.addedOrgs)
}

func authorizeDatasource(t *testing.T, ctx context.Context, id *authn.Identity, verb, name string) authorizer.Decision {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/apis/prometheus.datasource.grafana.app/v0alpha1/namespaces/default/datasources", nil)
	req = req.WithContext(ctx)
	res, ok, err := authenticator.NewAuthenticator().AuthenticateRequest(req)
	require.NoError(t, err)
	require.True(t, ok)

	decision, _, err := gfauthorizer.NewGrafanaBuiltInSTAuthorizer().Authorize(ctx, authorizer.AttributesRecord{
		User:            res.User,
		Verb:            verb,
		APIGroup:        "prometheus.datasource.grafana.app",
		APIVersion:      "v0alpha1",
		Resource:        "datasources",
		Name:            name,
		Namespace:       "default",
		ResourceRequest: true,
	})
	require.NoError(t, err)
	return decision
}

type recordingDataSources struct {
	datasources.DataSourceService
	listedOrgs []int64
	addedOrgs  []int64
}

func (r *recordingDataSources) GetDataSourcesByType(_ context.Context, query *datasources.GetDataSourcesByTypeQuery) ([]*datasources.DataSource, error) {
	r.listedOrgs = append(r.listedOrgs, query.OrgID)
	if query.OrgID != 1 {
		return nil, nil
	}
	return []*datasources.DataSource{{
		ID:    1,
		UID:   "prom-1",
		OrgID: 1,
		Name:  "Org One Prom",
		Type:  query.Type,
		URL:   "http://org-one.example",
		User:  "org-one-user",
	}}, nil
}

func (r *recordingDataSources) AddDataSource(_ context.Context, cmd *datasources.AddDataSourceCommand) (*datasources.DataSource, error) {
	r.addedOrgs = append(r.addedOrgs, cmd.OrgID)
	return &datasources.DataSource{
		ID:    2,
		UID:   cmd.UID,
		OrgID: cmd.OrgID,
		Name:  cmd.Name,
		Type:  cmd.Type,
		URL:   cmd.URL,
		User:  cmd.User,
	}, nil
}
