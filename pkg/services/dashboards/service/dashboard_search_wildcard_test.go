package service

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/apiserver/client"
	"github.com/grafana/grafana/pkg/services/dashboards"
)

func TestBuildDashboardSearchRequestBoundsWildcardText(t *testing.T) {
	k8sCli := new(client.MockK8sHandler)
	k8sCli.On("GetNamespace", mock.Anything).Return("default")
	service := &DashboardServiceImpl{k8sclient: k8sCli}

	cases := []struct {
		name  string
		title string
	}{
		{name: "many asterisks", title: strings.Repeat("*", 4000)},
		{name: "many question marks", title: strings.Repeat("?", 100)},
		{name: "asterisks and question marks inside text", title: "cpu*usage?now"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request, err := service.buildDashboardSearchRequest(&dashboards.FindPersistedDashboardsQuery{
				OrgId: 1,
				Title: tc.title,
			})
			if err != nil {
				return
			}
			require.NotNil(t, request)
			require.Truef(t, boundedSearchPattern(request.Query), "title %q became query %q", tc.title, request.Query)
		})
	}
}

func TestBuildDashboardSearchRequestKeepsOrdinaryContains(t *testing.T) {
	k8sCli := new(client.MockK8sHandler)
	k8sCli.On("GetNamespace", mock.Anything).Return("default")
	service := &DashboardServiceImpl{k8sclient: k8sCli}

	request, err := service.buildDashboardSearchRequest(&dashboards.FindPersistedDashboardsQuery{
		OrgId: 1,
		Title: "CPU Usage",
	})
	require.NoError(t, err)
	require.True(t, boundedSearchPattern(request.Query))
	require.Contains(t, request.Query, "cpu usage")
}
