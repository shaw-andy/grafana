package kvstore

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	"github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// These placeholders are not credentials. They only distinguish two rows.
const (
	cacheVictimValue   = "placeholder-victim-secret"
	cacheAttackerValue = "placeholder-attacker-secret"
)

// countingKV delegates to the real SQL store and counts Get calls so a test can
// see whether a cache hit was served for the wrong organization.
type countingKV struct {
	SecretsKVStore
	gets int
}

func (c *countingKV) Get(ctx context.Context, orgId int64, namespace, typ string) (string, bool, error) {
	c.gets++
	return c.SecretsKVStore.Get(ctx, orgId, namespace, typ)
}

func newCachedStore(t *testing.T) (*CachedKVStore, *countingKV) {
	t.Helper()
	sqlStore := db.InitTestDB(t) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore
	secretsService := manager.SetupTestService(t, fakes.NewFakeSecretsStore())
	sqlKV := NewSQLSecretsKVStore(sqlStore, secretsService, log.New("test.secrets.kvstore"))
	counter := &countingKV{SecretsKVStore: sqlKV}
	// Long TTL: these tests check key identity, not the production five-second expiry.
	return WithCache(counter, time.Minute, time.Minute), counter
}

func TestIntegrationCachedKVStoreOrgPrefixDoesNotShareEntries(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	ctx := context.Background()
	const (
		attackerOrg int64 = 1
		victimOrg   int64 = 12
		victimNS          = "prometheus"
		attackerNS        = "2prometheus"
		renamedNS         = "renamed"
		secretType        = DataSourceSecretType
	)

	t.Run("get and set keep each org on its own row", func(t *testing.T) {
		cached, counter := newCachedStore(t)
		require.NoError(t, cached.Set(ctx, attackerOrg, attackerNS, secretType, cacheAttackerValue))
		require.NoError(t, cached.Set(ctx, victimOrg, victimNS, secretType, cacheVictimValue))

		// The second Set must not replace the first org's cached value.
		got, ok, err := cached.Get(ctx, attackerOrg, attackerNS, secretType)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, cacheAttackerValue, got)
		require.Equal(t, 1, counter.gets)

		got, ok, err = cached.Get(ctx, victimOrg, victimNS, secretType)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, cacheVictimValue, got)
		// Both values were cached by Set, so neither Get may fall through.
		require.Equal(t, 1, counter.gets)
	})

	t.Run("get stores the row it loaded", func(t *testing.T) {
		cached, counter := newCachedStore(t)
		// Write through the SQL store so the cache starts empty.
		require.NoError(t, counter.SecretsKVStore.Set(ctx, attackerOrg, attackerNS, secretType, cacheAttackerValue))
		require.NoError(t, counter.SecretsKVStore.Set(ctx, victimOrg, victimNS, secretType, cacheVictimValue))

		got, ok, err := cached.Get(ctx, victimOrg, victimNS, secretType)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, cacheVictimValue, got)

		got, ok, err = cached.Get(ctx, attackerOrg, attackerNS, secretType)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, cacheAttackerValue, got)
		require.Equal(t, 2, counter.gets)
	})

	t.Run("delete removes only the named entry", func(t *testing.T) {
		cached, counter := newCachedStore(t)
		require.NoError(t, cached.Set(ctx, attackerOrg, attackerNS, secretType, cacheAttackerValue))
		require.NoError(t, cached.Set(ctx, victimOrg, victimNS, secretType, cacheVictimValue))

		require.NoError(t, cached.Del(ctx, attackerOrg, attackerNS, secretType))

		got, ok, err := cached.Get(ctx, victimOrg, victimNS, secretType)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, cacheVictimValue, got)
		// The victim value was cached by Set and must survive the other org's Del.
		require.Zero(t, counter.gets)

		_, ok, err = cached.Get(ctx, attackerOrg, attackerNS, secretType)
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("rename moves only the named entry", func(t *testing.T) {
		cached, counter := newCachedStore(t)
		require.NoError(t, cached.Set(ctx, attackerOrg, attackerNS, secretType, cacheAttackerValue))
		require.NoError(t, cached.Set(ctx, victimOrg, victimNS, secretType, cacheVictimValue))

		require.NoError(t, cached.Rename(ctx, attackerOrg, attackerNS, secretType, renamedNS))

		got, ok, err := cached.Get(ctx, attackerOrg, renamedNS, secretType)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, cacheAttackerValue, got)

		got, ok, err = cached.Get(ctx, victimOrg, victimNS, secretType)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, cacheVictimValue, got)
		require.Zero(t, counter.gets)

		_, ok, err = cached.Get(ctx, attackerOrg, attackerNS, secretType)
		require.NoError(t, err)
		require.False(t, ok)
	})
}
