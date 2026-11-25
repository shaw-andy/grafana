package common

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

func TestExtendInexactSearchTotal(t *testing.T) {
	fieldRows := func(n int) []*resourcepb.ResourceSearchRow {
		return make([]*resourcepb.ResourceSearchRow, n)
	}

	t.Run("full page with an inexact total points past the page", func(t *testing.T) {
		resp := &resourcepb.ResourceSearchResponse{Rows: fieldRows(2), TotalHits: 12}
		ExtendInexactSearchTotal(resp, 10, 2)
		require.Equal(t, int64(13), resp.TotalHits)
	})

	t.Run("a larger inexact total is kept", func(t *testing.T) {
		resp := &resourcepb.ResourceSearchResponse{Rows: fieldRows(2), TotalHits: 40}
		ExtendInexactSearchTotal(resp, 10, 2)
		require.Equal(t, int64(40), resp.TotalHits)
	})

	t.Run("table rows count too", func(t *testing.T) {
		resp := &resourcepb.ResourceSearchResponse{
			Results:   &resourcepb.ResourceTable{Rows: make([]*resourcepb.ResourceTableRow, 2)},
			TotalHits: 2,
		}
		ExtendInexactSearchTotal(resp, 0, 2)
		require.Equal(t, int64(3), resp.TotalHits)
	})

	t.Run("short page is left alone", func(t *testing.T) {
		resp := &resourcepb.ResourceSearchResponse{Rows: fieldRows(1), TotalHits: 11}
		ExtendInexactSearchTotal(resp, 10, 2)
		require.Equal(t, int64(11), resp.TotalHits)
	})

	t.Run("exact total is left alone", func(t *testing.T) {
		resp := &resourcepb.ResourceSearchResponse{Rows: fieldRows(2), TotalHits: 12, TotalHitsExact: true}
		ExtendInexactSearchTotal(resp, 10, 2)
		require.Equal(t, int64(12), resp.TotalHits)
	})

	t.Run("nil response is ignored", func(t *testing.T) {
		require.NotPanics(t, func() { ExtendInexactSearchTotal(nil, 0, 2) })
	})
}
