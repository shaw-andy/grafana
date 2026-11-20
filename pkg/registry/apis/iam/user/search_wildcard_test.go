package user

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/tracing"
	legacyuser "github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

func TestUserSearchBoundsWildcardQuery(t *testing.T) {
	cases := []string{
		strings.Repeat("*", 200),
		strings.Repeat("?", 100),
		"cpu*usage?",
	}
	for _, query := range cases {
		t.Run(query[:min(12, len(query))], func(t *testing.T) {
			sent, status := searchUsers(t, query)
			if status >= 400 && status < 500 {
				return
			}
			require.Truef(t, boundedSearchPattern(sent), "query %q was sent as %q (status %d)", query, sent, status)
		})
	}
}

func TestUserSearchKeepsOrdinaryContains(t *testing.T) {
	sent, status := searchUsers(t, "cpu")
	require.Less(t, status, 400)
	require.True(t, boundedSearchPattern(sent))
	require.Contains(t, sent, "cpu")
}

func searchUsers(t *testing.T, query string) (string, int) {
	t.Helper()
	mockClient := &MockClient{MockResponses: []*resourcepb.ResourceSearchResponse{{
		ResultFormat: resourcepb.ResourceSearchRequest_FIELD_VALUES,
	}}}
	handler := NewSearchHandler(tracing.NewNoopTracerService(), mockClient, &setting.Cfg{}, nil)

	params := url.Values{}
	params.Set("query", query)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/searchUsers?"+params.Encode(), nil)
	req = req.WithContext(identity.WithRequester(req.Context(), &legacyuser.SignedInUser{Namespace: "test"}))
	handler.DoSearch(rr, req)

	if mockClient.LastSearchRequest == nil {
		return "", rr.Code
	}
	return mockClient.LastSearchRequest.Query, rr.Code
}
