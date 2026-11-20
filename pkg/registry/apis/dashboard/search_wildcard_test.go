package dashboard

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/dashboards/dashboardaccess"
	"github.com/grafana/grafana/pkg/services/user"
)

func TestConvertSearchRequestBoundsWildcardQuery(t *testing.T) {
	user := &user.SignedInUser{Namespace: "default", OrgID: 1}
	noShared := func(dashboardaccess.PermissionType) ([]string, error) { return nil, nil }

	cases := []string{
		strings.Repeat("*", 4000),
		strings.Repeat("?", 100),
		"cpu*usage?",
	}
	for _, query := range cases {
		t.Run(query[:min(12, len(query))], func(t *testing.T) {
			params := url.Values{}
			params.Set("query", query)
			request, err := convertHttpSearchRequestToResourceSearchRequest(params, user, noShared)
			if err != nil {
				return
			}
			require.NotNil(t, request)
			require.Truef(t, boundedSearchPattern(request.Query), "query param became %q", request.Query)
		})
	}
}

func TestConvertSearchRequestKeepsOrdinaryQuery(t *testing.T) {
	params := url.Values{}
	params.Set("query", "cpu")
	request, err := convertHttpSearchRequestToResourceSearchRequest(params, &user.SignedInUser{Namespace: "default", OrgID: 1}, func(dashboardaccess.PermissionType) ([]string, error) {
		return nil, nil
	})
	require.NoError(t, err)
	require.Equal(t, "cpu", request.Query)
	require.True(t, boundedSearchPattern(request.Query))
}
