package folderimpl

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/apiserver/client"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

func TestSearchFoldersBoundsWildcardTitle(t *testing.T) {
	cases := []struct {
		name  string
		title string
		exact bool
	}{
		{name: "many asterisks", title: strings.Repeat("*", 4000)},
		{name: "many question marks", title: strings.Repeat("?", 100)},
		{name: "exact match keeps caller wildcards", title: "cpu*usage?", exact: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			query, status := searchFolderTitle(t, tc.title, tc.exact)
			if status != 0 {
				require.GreaterOrEqual(t, status, 400)
				require.Less(t, status, 500)
				return
			}
			require.Truef(t, boundedSearchPattern(query), "title %q became query %q", tc.title, query)
		})
	}
}

func TestSearchFoldersKeepsOrdinaryContains(t *testing.T) {
	query, status := searchFolderTitle(t, "CPU Usage", false)
	require.Zero(t, status)
	require.True(t, boundedSearchPattern(query))
	require.Contains(t, query, "cpu usage")
}

// searchFolderTitle runs SearchFolders. A non-zero status means the call
// failed before the index was asked to run a wildcard. Otherwise query is the
// text that was sent.
func searchFolderTitle(t *testing.T, title string, exact bool) (string, int) {
	t.Helper()
	fakeK8sClient := new(client.MockK8sHandler)
	fakeK8sClient.On("GetNamespace", mock.Anything).Return("default")
	var got string
	fakeK8sClient.On("Search", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			got = args.Get(2).(*resourcepb.ResourceSearchRequest).Query
		}).
		Return(&resourcepb.ResourceSearchResponse{
			ResultFormat: resourcepb.ResourceSearchRequest_FIELD_VALUES,
		}, nil)

	service := Service{
		k8sclient:     fakeK8sClient,
		features:      featuremgmt.WithFeatures(),
		tracer:        noop.NewTracerProvider().Tracer("TestSearchFoldersBoundsWildcardTitle"),
		accessControl: actest.FakeAccessControl{ExpectedEvaluate: true},
	}
	signedIn := &user.SignedInUser{OrgID: 1}
	ctx := identity.WithRequester(context.Background(), signedIn)
	_, err := service.SearchFolders(ctx, folder.SearchFoldersQuery{
		OrgID:           1,
		Title:           title,
		TitleExactMatch: exact,
		SignedInUser:    signedIn,
	})
	if err != nil {
		return "", 400
	}
	return got, 0
}
