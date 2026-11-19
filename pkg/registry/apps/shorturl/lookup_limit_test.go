package shorturl

import (
	"context"
	"errors"
	"testing"
	"time"

	claims "github.com/grafana/authlib/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/storage"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
)

func newTestLimiter(now *time.Time) *lookupLimiter {
	l := newLookupLimiter()
	l.now = func() time.Time { return *now }
	return l
}

func TestLookupLimiter(t *testing.T) {
	t.Run("refuses once the miss budget is spent and refills over time", func(t *testing.T) {
		now := time.Unix(1000, 0)
		l := newTestLimiter(&now)

		for i := 0; i < lookupMissBurst; i++ {
			require.True(t, l.reserve("org-1/user:a"), "reserve %d", i)
		}
		require.False(t, l.reserve("org-1/user:a"))

		now = now.Add(lookupMissRefill - time.Second)
		require.False(t, l.reserve("org-1/user:a"))

		now = now.Add(time.Second)
		require.True(t, l.reserve("org-1/user:a"))
		require.False(t, l.reserve("org-1/user:a"))
	})

	t.Run("a released reservation does not count as a miss", func(t *testing.T) {
		now := time.Unix(1000, 0)
		l := newTestLimiter(&now)

		for i := 0; i < 3*lookupMissBurst; i++ {
			require.True(t, l.reserve("org-1/user:a"))
			l.release("org-1/user:a")
		}
	})

	t.Run("budgets are per user", func(t *testing.T) {
		now := time.Unix(1000, 0)
		l := newTestLimiter(&now)

		for i := 0; i < lookupMissBurst; i++ {
			require.True(t, l.reserve("org-1/user:a"))
		}
		require.False(t, l.reserve("org-1/user:a"))
		require.True(t, l.reserve("org-1/user:b"))
		require.True(t, l.reserve("org-2/user:a"))
	})

	t.Run("sweep drops refilled budgets", func(t *testing.T) {
		now := time.Unix(1000, 0)
		l := newTestLimiter(&now)

		require.True(t, l.reserve("org-1/user:a"))
		now = now.Add(lookupMissRefill + lookupSweepEvery)
		require.True(t, l.reserve("org-1/user:b"))
		assert.NotContains(t, l.budgets, "org-1/user:a")
	})
}

type fakeStorage struct {
	storage.Interface
	err   error
	calls int
}

func (f *fakeStorage) Get(_ context.Context, _ string, _ storage.GetOptions, _ runtime.Object) error {
	f.calls++
	return f.err
}

func TestLookupLimitedStorage(t *testing.T) {
	user := &identity.StaticRequester{Type: claims.TypeUser, UserUID: "a", Namespace: "default"}
	userCtx := identity.WithRequester(context.Background(), user)
	notFound := storage.NewKeyNotFoundError("/shorturls/default/missing", 0)

	t.Run("misses are refused with 429 once the budget is spent", func(t *testing.T) {
		inner := &fakeStorage{err: notFound}
		s := &lookupLimitedStorage{Interface: inner, limiter: newLookupLimiter()}

		for i := 0; i < lookupMissBurst; i++ {
			err := s.Get(userCtx, "key", storage.GetOptions{}, nil)
			require.True(t, storage.IsNotFound(err), "lookup %d: %v", i, err)
		}

		err := s.Get(userCtx, "key", storage.GetOptions{}, nil)
		require.True(t, apierrors.IsTooManyRequests(err), "got %v", err)
		_, hasDelay := apierrors.SuggestsClientDelay(err)
		require.False(t, hasDelay)
		require.Equal(t, lookupMissBurst, inner.calls, "refused lookups must not reach storage")

		inner.err = nil
		err = s.Get(userCtx, "key", storage.GetOptions{}, nil)
		require.True(t, apierrors.IsTooManyRequests(err), "a refused user cannot read an existing short URL either")
	})

	t.Run("found and failed lookups do not use the budget", func(t *testing.T) {
		inner := &fakeStorage{}
		s := &lookupLimitedStorage{Interface: inner, limiter: newLookupLimiter()}

		for i := 0; i < 2*lookupMissBurst; i++ {
			require.NoError(t, s.Get(userCtx, "key", storage.GetOptions{}, nil))
		}
		inner.err = errors.New("backend unavailable")
		for i := 0; i < 2*lookupMissBurst; i++ {
			require.EqualError(t, s.Get(userCtx, "key", storage.GetOptions{}, nil), "backend unavailable")
		}
	})

	t.Run("service identity is not limited", func(t *testing.T) {
		inner := &fakeStorage{err: notFound}
		s := &lookupLimitedStorage{Interface: inner, limiter: newLookupLimiter()}
		svcCtx, _ := identity.WithServiceIdentity(context.Background(), 1)

		for i := 0; i < 2*lookupMissBurst; i++ {
			require.True(t, storage.IsNotFound(s.Get(svcCtx, "key", storage.GetOptions{}, nil)))
		}
	})
}
