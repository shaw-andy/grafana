package annotationsimpl

import (
	"context"
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"testing"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/annotations"
	"github.com/grafana/grafana/pkg/services/annotations/accesscontrol"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/xorm/core"
)

// maxAnnotationLimit matches the cap enforced by dashboard search. A caller-supplied
// annotation limit above this must not become a slice capacity or a SQL LIMIT.
const maxAnnotationLimit int64 = 5000

func TestFindDoesNotAllocateCallerLimitBeforeAuthorization(t *testing.T) {
	// 8e6 pointers is the same make([]*ItemDTO, 0, q.Limit) as the 2e9 attack
	// value, and about 64MiB on 64-bit. The attack value itself is covered by
	// the HTTP and SQL tests; allocating it here would exhaust the test process.
	const probeLimit int64 = 8_000_000
	halfAllocation := uint64(probeLimit) * uint64(unsafe.Sizeof((*annotations.ItemDTO)(nil))) / 2

	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	auth := &limitProbeAuth{baseline: before.TotalAlloc}
	reader := &limitProbeReader{}
	repo := NewRepositoryImpl(auth, featuremgmt.WithFeatures(), reader, nil)

	items, err := repo.Find(context.Background(), &annotations.ItemQuery{
		OrgID:        1,
		DashboardUID: "any",
		Limit:        probeLimit,
		SignedInUser: viewer(),
	})

	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if auth.called {
		require.Lessf(t, auth.allocated, halfAllocation,
			"Find allocated the caller limit before Authorize; TotalAlloc grew by %d bytes", auth.allocated)
	}
	require.Lessf(t, after.TotalAlloc-before.TotalAlloc, halfAllocation,
		"Find allocated the caller limit; TotalAlloc grew by %d bytes", after.TotalAlloc-before.TotalAlloc)
	if reader.calls > 0 {
		require.LessOrEqual(t, reader.lastLimit, maxAnnotationLimit)
		require.GreaterOrEqual(t, reader.lastLimit, int64(0))
	}
	if err == nil {
		require.LessOrEqual(t, int64(cap(items)), maxAnnotationLimit)
	}
}

func TestFindDoesNotAllocateCallerLimitForDashboardID(t *testing.T) {
	const probeLimit int64 = 8_000_000
	halfAllocation := uint64(probeLimit) * uint64(unsafe.Sizeof((*annotations.ItemDTO)(nil))) / 2

	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	auth := &limitProbeAuth{baseline: before.TotalAlloc}
	reader := &limitProbeReader{}
	repo := NewRepositoryImpl(auth, featuremgmt.WithFeatures(), reader, nil)

	_, err := repo.Find(context.Background(), &annotations.ItemQuery{
		OrgID:        1,
		DashboardID:  7,
		Limit:        probeLimit,
		SignedInUser: viewer(),
	})

	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	require.Less(t, after.TotalAlloc-before.TotalAlloc, halfAllocation)
	if auth.called {
		require.Less(t, auth.allocated, halfAllocation)
	}
	if reader.calls > 0 {
		require.LessOrEqual(t, reader.lastLimit, maxAnnotationLimit)
	}
	if err == nil && reader.calls > 0 {
		require.GreaterOrEqual(t, reader.lastLimit, int64(0))
	}
}

func TestFindRejectsLimitThatOverflowsSliceAllocation(t *testing.T) {
	reader := &limitProbeReader{}
	repo := NewRepositoryImpl(&limitProbeAuth{}, featuremgmt.WithFeatures(), reader, nil)

	require.NotPanics(t, func() {
		items, err := repo.Find(context.Background(), &annotations.ItemQuery{
			OrgID:        1,
			DashboardUID: "any",
			Limit:        int64(^uint64(0) >> 1), // math.MaxInt64, a legal QueryInt64 value
			SignedInUser: viewer(),
		})
		if err == nil {
			require.LessOrEqual(t, int64(cap(items)), maxAnnotationLimit)
		}
		if reader.calls > 0 {
			require.LessOrEqual(t, reader.lastLimit, maxAnnotationLimit)
		}
	})
}

func TestFindRejectsNegativeLimit(t *testing.T) {
	reader := &limitProbeReader{}
	repo := NewRepositoryImpl(&limitProbeAuth{}, featuremgmt.WithFeatures(), reader, nil)

	require.NotPanics(t, func() {
		items, err := repo.Find(context.Background(), &annotations.ItemQuery{
			OrgID:        1,
			DashboardUID: "any",
			Limit:        -1,
			SignedInUser: viewer(),
		})
		if err == nil {
			require.LessOrEqual(t, int64(cap(items)), maxAnnotationLimit)
		}
		if reader.calls > 0 {
			require.GreaterOrEqual(t, reader.lastLimit, int64(0))
			require.LessOrEqual(t, reader.lastLimit, maxAnnotationLimit)
		}
	})
}

func TestFindWithoutDashboardStillBoundsLimit(t *testing.T) {
	// No dashboard id skips the allocation and queries first. The limit must
	// already be bounded on that call: it is the value interpolated into SQL.
	reader := &limitProbeReader{}
	repo := NewRepositoryImpl(&limitProbeAuth{}, featuremgmt.WithFeatures(), reader, nil)

	_, err := repo.Find(context.Background(), &annotations.ItemQuery{
		OrgID:        1,
		Limit:        2_000_000_000,
		SignedInUser: viewer(),
	})
	require.NoError(t, err)
	require.NotZero(t, reader.calls)
	require.LessOrEqual(t, reader.lastLimit, maxAnnotationLimit)
	require.GreaterOrEqual(t, reader.lastLimit, int64(0))
	require.True(t, reader.sawSkipAccessControl)
}

func TestFindKeepsLimitAtSearchCap(t *testing.T) {
	reader := &limitProbeReader{items: []*annotations.ItemDTO{{ID: 1}}}
	repo := NewRepositoryImpl(&limitProbeAuth{}, featuremgmt.WithFeatures(), reader, nil)

	items, err := repo.Find(context.Background(), &annotations.ItemQuery{
		OrgID:        1,
		DashboardUID: "dash",
		Limit:        maxAnnotationLimit,
		SignedInUser: viewer(),
	})
	require.NoError(t, err)
	require.NotEmpty(t, items)
	require.Equal(t, maxAnnotationLimit, reader.lastLimit)
}

func TestXormStoreBoundsSQLLimit(t *testing.T) {
	store := db.NewTestStore(t)
	logger := &sqlCapture{showSQL: true}
	engine := store.GetEngine()
	engine.SetLogger(logger)
	engine.ShowSQL(true)

	repo := NewXormStore(setting.NewCfg(), log.New("annotation.limit.test"), store, nil, prometheus.NewRegistry())
	ctx := context.Background()

	t.Run("item query", func(t *testing.T) {
		logger.messages = nil
		err := queryItems(t, repo, ctx, 2_000_000_000)
		require.NoError(t, err)
		assertSQLLimitBounded(t, logger.messages)

		logger.messages = nil
		err = queryItems(t, repo, ctx, 5001)
		require.NoError(t, err)
		assertSQLLimitBounded(t, logger.messages)
	})

	t.Run("tag query", func(t *testing.T) {
		logger.messages = nil
		_, err := repo.GetTags(ctx, annotations.TagsQuery{OrgID: 1, Limit: 2_000_000_000})
		require.NoError(t, err)
		assertSQLLimitBounded(t, logger.messages)

		logger.messages = nil
		_, err = repo.GetTags(ctx, annotations.TagsQuery{OrgID: 1, Limit: 5001})
		require.NoError(t, err)
		assertSQLLimitBounded(t, logger.messages)
	})
}

func queryItems(t *testing.T, repo *xormRepositoryImpl, ctx context.Context, limit int64) error {
	t.Helper()
	_, err := repo.Get(ctx, annotations.ItemQuery{
		OrgID:        1,
		DashboardUID: "any",
		Limit:        limit,
	}, &accesscontrol.AccessResources{SkipAccessControlFilter: true})
	return err
}

var sqlLimitPattern = regexp.MustCompile(`LIMIT\s+(-?\d+)`)

func assertSQLLimitBounded(t *testing.T, messages []string) {
	t.Helper()
	require.NotEmpty(t, messages, "annotation query did not execute SQL")

	found := false
	for _, msg := range messages {
		matches := sqlLimitPattern.FindAllStringSubmatch(msg, -1)
		for _, match := range matches {
			found = true
			limit, err := strconv.ParseInt(match[1], 10, 64)
			require.NoError(t, err)
			require.LessOrEqualf(t, limit, maxAnnotationLimit, "SQL used caller limit in %s", msg)
			require.GreaterOrEqualf(t, limit, int64(0), "SQL used caller limit in %s", msg)
		}
	}
	require.True(t, found, "executed SQL had no LIMIT: %v", messages)
}

type limitProbeAuth struct {
	baseline  uint64
	allocated uint64
	called    bool
}

func (p *limitProbeAuth) Authorize(context.Context, annotations.ItemQuery) (*accesscontrol.AccessResources, error) {
	var now runtime.MemStats
	runtime.ReadMemStats(&now)
	p.called = true
	if now.TotalAlloc >= p.baseline {
		p.allocated = now.TotalAlloc - p.baseline
	}
	return &accesscontrol.AccessResources{
		Dashboards: map[string]int64{"any": 1, "dash": 2},
	}, nil
}

type limitProbeReader struct {
	items                []*annotations.ItemDTO
	lastLimit            int64
	calls                int
	sawSkipAccessControl bool
}

func (r *limitProbeReader) Type() string { return "limit-probe" }

func (r *limitProbeReader) Get(_ context.Context, query annotations.ItemQuery, resources *accesscontrol.AccessResources) ([]*annotations.ItemDTO, error) {
	r.calls++
	r.lastLimit = query.Limit
	if resources != nil && resources.SkipAccessControlFilter {
		r.sawSkipAccessControl = true
	}
	return r.items, nil
}

func (r *limitProbeReader) GetTags(context.Context, annotations.TagsQuery) (annotations.FindTagsResult, error) {
	return annotations.FindTagsResult{}, nil
}

func viewer() *user.SignedInUser {
	return &user.SignedInUser{UserID: 1, OrgID: 1}
}

type sqlCapture struct {
	messages []string
	showSQL  bool
	level    core.LogLevel
}

func (s *sqlCapture) Debug(v ...any)        {}
func (s *sqlCapture) Debugf(string, ...any) {}
func (s *sqlCapture) Error(v ...any)        {}
func (s *sqlCapture) Errorf(string, ...any) {}
func (s *sqlCapture) Info(v ...any)         {}
func (s *sqlCapture) Infof(format string, v ...any) {
	s.messages = append(s.messages, fmt.Sprintf(format, v...))
}
func (s *sqlCapture) Warn(v ...any)            {}
func (s *sqlCapture) Warnf(string, ...any)     {}
func (s *sqlCapture) Level() core.LogLevel     { return s.level }
func (s *sqlCapture) SetLevel(l core.LogLevel) { s.level = l }
func (s *sqlCapture) ShowSQL(show ...bool) {
	if len(show) == 0 {
		s.showSQL = true
		return
	}
	s.showSQL = show[0]
}
func (s *sqlCapture) IsShowSQL() bool { return s.showSQL }
