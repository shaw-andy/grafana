package team

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

func TestTeamSearchBoundsWildcardQuery(t *testing.T) {
	cases := []string{
		strings.Repeat("*", 4000),
		strings.Repeat("?", 100),
		"cpu*usage?",
	}
	for _, query := range cases {
		t.Run(query[:min(12, len(query))], func(t *testing.T) {
			sent, status := searchTeams(t, query)
			if status >= 400 && status < 500 {
				return
			}
			require.Truef(t, boundedSearchPattern(sent), "query %q was sent as %q (status %d)", query, sent, status)
		})
	}
}

func TestTeamSearchKeepsOrdinaryQuery(t *testing.T) {
	sent, status := searchTeams(t, "cpu")
	require.Less(t, status, 400)
	require.Equal(t, "cpu", sent)
	require.True(t, boundedSearchPattern(sent))
}

func searchTeams(t *testing.T, query string) (string, int) {
	t.Helper()
	mockClient := &MockClient{MockResponses: []*resourcepb.ResourceSearchResponse{{
		ResultFormat: resourcepb.ResourceSearchRequest_FIELD_VALUES,
	}}}
	handler := SearchHandler{
		log:    log.New("grafana-apiserver.teams.search"),
		client: mockClient,
		tracer: tracing.NewNoopTracerService(),
	}

	params := url.Values{}
	params.Set("query", query)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/teams/search?"+params.Encode(), nil)
	req = req.WithContext(identity.WithRequester(req.Context(), &user.SignedInUser{Namespace: "test"}))
	handler.DoTeamSearch(rr, req)

	if mockClient.LastSearchRequest == nil {
		return "", rr.Code
	}
	return mockClient.LastSearchRequest.Query, rr.Code
}
