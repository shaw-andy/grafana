package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/search/model"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/web/webtest"
)

func TestHTTPServer_SearchQueryLength(t *testing.T) {
	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.SearchService = &mockSearchService{ExpectedResult: model.HitList{}}
	})

	search := func(t *testing.T, query string) int {
		t.Helper()
		req := server.NewGetRequest("/api/search/?query=" + url.QueryEscape(query))
		webtest.RequestWithSignedInUser(req, &user.SignedInUser{UserID: 1, OrgID: 1})
		res, err := server.Send(req)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		return res.StatusCode
	}

	require.Equal(t, http.StatusOK, search(t, strings.Repeat("a", resource.MaxSearchTextLength)))
	require.Equal(t, http.StatusUnprocessableEntity, search(t, strings.Repeat("a", resource.MaxSearchTextLength+1)))
	require.Equal(t, http.StatusUnprocessableEntity, search(t, strings.Repeat("*", 4000)))
}
