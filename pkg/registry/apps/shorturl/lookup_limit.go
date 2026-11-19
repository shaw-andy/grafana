package shorturl

import (
	"context"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"
	"k8s.io/client-go/tools/cache"

	appsdkapiserver "github.com/grafana/grafana-app-sdk/k8s/apiserver"
	shorturl "github.com/grafana/grafana/apps/shorturl/pkg/apis/shorturl/v1beta1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
)

const (
	// lookupMissBurst is how many lookups of short URLs that do not exist one
	// user can make before being refused. Opening a short URL that exists is
	// never limited, and following a dead link is rare, so legitimate use stays
	// well under this.
	lookupMissBurst = 10
	// lookupMissRefill is how long it takes to earn back one refused lookup.
	lookupMissRefill = 6 * time.Minute
	lookupSweepEvery = time.Minute
)

// lookupLimiter keeps a per-user budget of short URL lookups that found
// nothing. Every signed-in user in an org can read any short URL whose name
// they know, so these misses are what guessing a name costs.
type lookupLimiter struct {
	burst  float64
	refill time.Duration
	now    func() time.Time

	mu        sync.Mutex
	budgets   map[string]*missBudget
	lastSweep time.Time
}

type missBudget struct {
	tokens float64
	at     time.Time
}

func newLookupLimiter() *lookupLimiter {
	return &lookupLimiter{
		burst:   lookupMissBurst,
		refill:  lookupMissRefill,
		now:     time.Now,
		budgets: make(map[string]*missBudget),
	}
}

// reserve takes one miss from key's budget before the lookup runs, so
// concurrent lookups cannot spend more than the budget holds. The caller gives
// it back with release when the lookup finds a short URL.
func (l *lookupLimiter) reserve(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweep(now)

	b, ok := l.budgets[key]
	if !ok {
		b = &missBudget{tokens: l.burst, at: now}
		l.budgets[key] = b
	} else {
		l.refillBudget(b, now)
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *lookupLimiter) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if b, ok := l.budgets[key]; ok {
		b.tokens = min(l.burst, b.tokens+1)
	}
}

func (l *lookupLimiter) refillBudget(b *missBudget, now time.Time) {
	if elapsed := now.Sub(b.at); elapsed > 0 {
		b.tokens = min(l.burst, b.tokens+float64(elapsed)/float64(l.refill))
		b.at = now
	}
}

// sweep drops budgets that have refilled completely, which behave the same as
// a missing one, so memory only holds users with recent misses.
func (l *lookupLimiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < lookupSweepEvery {
		return
	}
	for key, b := range l.budgets {
		l.refillBudget(b, now)
		if b.tokens >= l.burst {
			delete(l.budgets, key)
		}
	}
	l.lastSweep = now
}

// lookupLimitedStorage applies the lookup limit to every single-object read of
// short URLs. The resource, its status subresource and the goto route all read
// through this storage, so no read path skips the limit.
type lookupLimitedStorage struct {
	storage.Interface
	limiter *lookupLimiter
}

func (s *lookupLimitedStorage) Get(ctx context.Context, key string, opts storage.GetOptions, objPtr runtime.Object) error {
	requester, err := identity.GetRequester(ctx)
	if err != nil || identity.IsServiceIdentity(ctx) {
		return s.Interface.Get(ctx, key, opts, objPtr)
	}

	limitKey := requester.GetNamespace() + "/" + requester.GetUID()
	if !s.limiter.reserve(limitKey) {
		// No Retry-After: client-go retries a 429 that carries one, which would
		// stall the in-process calls made by /goto and /api/short-urls.
		return apierrors.NewTooManyRequests("too many lookups of short URLs that do not exist, try again later", 0)
	}

	err = s.Interface.Get(ctx, key, opts, objPtr)
	if !storage.IsNotFound(err) {
		s.limiter.release(limitKey)
	}
	return err
}

// lookupLimitedOptionsGetter wraps the storage built for short URLs in
// lookupLimitedStorage and leaves every other resource unchanged.
type lookupLimitedOptionsGetter struct {
	inner   generic.RESTOptionsGetter
	limiter *lookupLimiter
}

var _ appsdkapiserver.RESTOptionsGetterForResource = (*lookupLimitedOptionsGetter)(nil)

func (g *lookupLimitedOptionsGetter) GetRESTOptions(resource schema.GroupResource, example runtime.Object) (generic.RESTOptions, error) {
	opts, err := g.inner.GetRESTOptions(resource, example)
	if err != nil || resource != shorturl.ShortURLKind().GroupVersionResource().GroupResource() {
		return opts, err
	}

	decorator := opts.Decorator
	if decorator == nil {
		decorator = generic.UndecoratedStorage
	}
	opts.Decorator = func(
		config *storagebackend.ConfigForResource,
		resourcePrefix string,
		keyFunc func(obj runtime.Object) (string, error),
		newFunc func() runtime.Object,
		newListFunc func() runtime.Object,
		getAttrsFunc storage.AttrFunc,
		trigger storage.IndexerFuncs,
		indexers *cache.Indexers,
	) (storage.Interface, factory.DestroyFunc, error) {
		inner, destroy, err := decorator(config, resourcePrefix, keyFunc, newFunc, newListFunc, getAttrsFunc, trigger, indexers)
		if err != nil {
			return nil, nil, err
		}
		return &lookupLimitedStorage{Interface: inner, limiter: g.limiter}, destroy, nil
	}
	return opts, nil
}

func (g *lookupLimitedOptionsGetter) ForResource(gvr schema.GroupVersionResource) generic.RESTOptionsGetter {
	forResource, ok := g.inner.(appsdkapiserver.RESTOptionsGetterForResource)
	if !ok {
		return nil
	}
	scoped := forResource.ForResource(gvr)
	if scoped == nil {
		return nil
	}
	return &lookupLimitedOptionsGetter{inner: scoped, limiter: g.limiter}
}
