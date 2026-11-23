package shorturlimpl

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/shorturls"
	"github.com/grafana/grafana/pkg/services/user"
)

// recordingStore counts inserts so a path that should be refused cannot be
// persisted first and rejected afterwards.
type recordingStore struct {
	inserts []*shorturls.ShortUrl
}

func (s *recordingStore) Get(context.Context, identity.Requester, string) (*shorturls.ShortUrl, error) {
	return nil, shorturls.ErrShortURLNotFound.Errorf("short URL not found")
}

func (s *recordingStore) Update(context.Context, *shorturls.ShortUrl) error { return nil }

func (s *recordingStore) Insert(_ context.Context, shortURL *shorturls.ShortUrl) error {
	s.inserts = append(s.inserts, shortURL)
	return nil
}

func (s *recordingStore) Delete(context.Context, *shorturls.DeleteShortUrlCommand) error { return nil }

func (s *recordingStore) List(context.Context, int64) ([]*shorturls.ShortUrl, error) {
	return nil, nil
}

func TestCreateShortURLRejectsEncodedDotSegments(t *testing.T) {
	viewer := &user.SignedInUser{UserID: 1, OrgID: 1, OrgRole: identity.RoleViewer}

	t.Run("stores an ordinary relative path", func(t *testing.T) {
		store := &recordingStore{}
		svc := ShortURLService{SQLStore: store}
		created, err := svc.CreateShortURL(context.Background(), viewer, &dtos.CreateShortURLCmd{
			Path: "d/abc/dashboard?orgId=1",
		})
		require.NoError(t, err)
		require.NotNil(t, created)
		require.Len(t, store.inserts, 1)
		require.Equal(t, "d/abc/dashboard?orgId=1", store.inserts[0].Path)
	})

	// A signed-in viewer can call CreateShortURL. These paths do not contain the
	// literal characters "../", but a browser resolves them out of a subpath.
	paths := []string{
		"..",
		"%2e%2e",
		"%2e%2e/other-app/action",
		"%2E%2E/other-app/action",
		".%2e/other-app/action",
		"%2e./other-app/action",
		"d/%2e%2e/%2e%2e/other-app/action",
		"%2e%2e%2fother-app/action",
		"..%2fother-app/action",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			store := &recordingStore{}
			svc := ShortURLService{SQLStore: store}
			created, err := svc.CreateShortURL(context.Background(), viewer, &dtos.CreateShortURLCmd{
				Path: path,
			})
			require.Error(t, err)
			require.Nil(t, created)
			require.Empty(t, store.inserts)
		})
	}
}
