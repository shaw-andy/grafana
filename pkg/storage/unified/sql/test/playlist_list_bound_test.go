package test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/authlib/types"
	"github.com/grafana/dskit/services"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// playlistListPageBytes is the unified storage list page budget used when
// max_page_size_bytes is unset. resource.NewUninitializedResourceServer
// substitutes this value for a non-positive MaxPageSizeBytes.
const playlistListPageBytes = 2 * 1024 * 1024

// TestIntegrationPlaylistListDoesNotReadEveryBody stores several playlist
// documents that together exceed one list page, then lists them the way
// GET /api/playlists does (no limit) and the way a capped list would (limit 1).
//
// The list must stop reading stored bodies once the page budget, or the
// requested limit, is satisfied. Reading every body in the authorization
// batch first keeps each playlist's item list in memory even though the
// response is only one page.
func TestIntegrationPlaylistListDoesNotReadEveryBody(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)
	t.Cleanup(db.CleanupTestDB)

	const (
		group     = "playlist.grafana.app"
		plural    = "playlists"
		namespace = "default"
		padding   = 180 * 1024
		count     = 16
	)

	backend := newTestBackend(t, !db.IsTestDbSQLite(), 0, 0)
	if svc, ok := backend.(services.Service); ok {
		t.Cleanup(func() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = services.StopAndAwaitTerminated(stopCtx, svc)
		})
	}
	counting := &byteCountingBackend{StorageBackend: backend}

	srv, err := resource.NewResourceServer(resource.ResourceServerOptions{
		Backend:          counting,
		AccessClient:     types.FixedAccessClient(true),
		MaxPageSizeBytes: playlistListPageBytes,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Stop(stopCtx)
	})

	ctx := types.WithAuthInfo(context.Background(), &identity.StaticRequester{
		Type:           types.TypeUser,
		Login:          "playlist-list-test",
		UserID:         7,
		UserUID:        "playlist-list-test",
		Namespace:      "*",
		OrgRole:        identity.RoleAdmin,
		IsGrafanaAdmin: true,
	})

	var storedObjectBytes int
	for i := range count {
		name := fmt.Sprintf("pl-%02d", i)
		raw := playlistDocument(name, namespace, padding)
		if storedObjectBytes == 0 {
			storedObjectBytes = len(raw)
		}
		rsp, err := srv.Create(ctx, &resourcepb.CreateRequest{
			Key: &resourcepb.ResourceKey{
				Namespace: namespace,
				Group:     group,
				Resource:  plural,
				Name:      name,
			},
			Value: raw,
		})
		requireNoResourceError(t, err, rsp, "create "+name)
	}
	require.Greater(t, count*storedObjectBytes, playlistListPageBytes)

	list := func(limit int64) (*resourcepb.ListResponse, int) {
		t.Helper()
		counting.scanned = 0
		rsp, err := srv.List(ctx, &resourcepb.ListRequest{
			Limit: limit,
			Options: &resourcepb.ListOptions{
				Key: &resourcepb.ResourceKey{
					Namespace: namespace,
					Group:     group,
					Resource:  plural,
				},
			},
		})
		requireNoResourceError(t, err, rsp, "list")
		require.NotEmpty(t, rsp.Items)
		return rsp, counting.scanned
	}

	// One extra body is the lookahead that tells the server another page exists.
	// Anything beyond that was read before the page budget or the limit applied.
	allowance := func(rsp *resourcepb.ListResponse) int {
		return listedBytes(rsp) + largestItem(rsp)
	}

	t.Run("empty limit still stops at the page budget", func(t *testing.T) {
		rsp, scanned := list(0)
		require.LessOrEqual(t, scanned, allowance(rsp),
			"list with no limit read %d stored bytes to return %d; the rest of the playlist bodies stayed in memory",
			scanned, listedBytes(rsp))
	})

	t.Run("limit one does not read the other playlist bodies", func(t *testing.T) {
		rsp, scanned := list(1)
		require.Len(t, rsp.Items, 1)
		require.LessOrEqual(t, scanned, allowance(rsp),
			"list limit 1 read %d stored bytes to return %d", scanned, listedBytes(rsp))
	})
}

type resourceErrorResult interface {
	GetError() *resourcepb.ErrorResult
}

func requireNoResourceError(t *testing.T, err error, rsp resourceErrorResult, what string) {
	t.Helper()
	require.NoError(t, err)
	require.NotNil(t, rsp)
	if got := rsp.GetError(); got != nil {
		t.Fatalf("%s: %s", what, got.GetMessage())
	}
}

func largestItem(rsp *resourcepb.ListResponse) int {
	largest := 0
	for _, item := range rsp.GetItems() {
		if n := len(item.GetValue()); n > largest {
			largest = n
		}
	}
	return largest
}

func listedBytes(rsp *resourcepb.ListResponse) int {
	total := 0
	for _, item := range rsp.GetItems() {
		total += len(item.GetValue())
	}
	return total
}

func playlistDocument(name, namespace string, valueBytes int) []byte {
	padding := strings.Repeat("x", valueBytes)
	return []byte(fmt.Sprintf(`{
		"apiVersion": "playlist.grafana.app/v1",
		"kind": "Playlist",
		"metadata": {"name": %q, "namespace": %q},
		"spec": {
			"title": %q,
			"interval": "5s",
			"items": [{"type": "dashboard_by_uid", "value": %q}]
		}
	}`, name, namespace, name, padding))
}

// byteCountingBackend counts bytes the real backend yields from ListIterator.
// Every other call goes to the SQL backend unchanged.
type byteCountingBackend struct {
	resource.StorageBackend
	scanned int
}

func (b *byteCountingBackend) ListIterator(ctx context.Context, req *resourcepb.ListRequest, cb func(resource.ListIterator) error) (int64, error) {
	return b.StorageBackend.ListIterator(ctx, req, func(iter resource.ListIterator) error {
		return cb(&byteCountingIter{ListIterator: iter, backend: b})
	})
}

type byteCountingIter struct {
	resource.ListIterator
	backend *byteCountingBackend
}

func (it *byteCountingIter) Next() bool {
	ok := it.ListIterator.Next()
	if ok && it.ListIterator.Error() == nil {
		it.backend.scanned += len(it.Value())
	}
	return ok
}
