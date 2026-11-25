package search

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	model "github.com/grafana/grafana/apps/alerting/rules/pkg/apis/alerting/v0alpha1"
	"github.com/grafana/grafana/pkg/registry/apps/alerting/rules/alertrule"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

type fixedSearchClient struct {
	resourcepb.ResourceIndexClient
	resp *resourcepb.ResourceSearchResponse
}

func (c *fixedSearchClient) Search(context.Context, *resourcepb.ResourceSearchRequest, ...grpc.CallOption) (*resourcepb.ResourceSearchResponse, error) {
	return c.resp, nil
}

func TestRunNextCursor(t *testing.T) {
	rows := func(n int) *resourcepb.ResourceTable {
		return &resourcepb.ResourceTable{Rows: make([]*resourcepb.ResourceTableRow, n)}
	}
	limit := int64(2)
	body := model.CreateSearchRulesRequestBody{Limit: &limit}
	gr := alertrule.ResourceInfo.GroupResource()

	tests := []struct {
		name     string
		resp     *resourcepb.ResourceSearchResponse
		wantNext bool
	}{
		{
			name:     "exact total past the page",
			resp:     &resourcepb.ResourceSearchResponse{Results: rows(2), TotalHits: 5, TotalHitsExact: true},
			wantNext: true,
		},
		{
			name: "exact total reached",
			resp: &resourcepb.ResourceSearchResponse{Results: rows(2), TotalHits: 2, TotalHitsExact: true},
		},
		{
			// Post-rank authorization stops once the page is full and counts only
			// the authorized hits it saw.
			name:     "inexact total after a full page",
			resp:     &resourcepb.ResourceSearchResponse{Results: rows(2), TotalHits: 2},
			wantNext: true,
		},
		{
			name: "inexact total after a short page",
			resp: &resourcepb.ResourceSearchResponse{Results: rows(1), TotalHits: 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler(&fixedSearchClient{resp: tt.resp}, nil)
			_, next, err := h.run(context.Background(), body, "default", gr, nil)
			require.NoError(t, err)
			if tt.wantNext {
				require.Equal(t, encodeCursor(2), next)
			} else {
				require.Empty(t, next)
			}
		})
	}
}
