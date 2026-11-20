package database

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/publicdashboards/internal/models"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/xorm/core"
)

// maxPublicDashboardListPageSize is the most dashboard_public rows one list
// request may materialize. It is the page size ListPublicDashboards already
// uses when perpage is omitted, and it is the cap a larger perpage must hit.
const maxPublicDashboardListPageSize = 1000

// TestPublicDashboardListQueryIsBounded is the spec for the list store query.
// It fails while FindAll reads every sharing row for the org, including each
// access token, and passes once that query applies the requested page and
// refuses a limit above maxPublicDashboardListPageSize.
func TestPublicDashboardListQueryIsBounded(t *testing.T) {
	const (
		orgID     = int64(7)
		otherOrg  = int64(8)
		pageSize  = 1
		rowCount  = 4
		hugeLimit = 500000
	)

	sqlStore := db.NewTestStore(t)
	cfg := setting.NewCfg()
	store := ProvideStore(sqlStore, cfg, featuremgmt.WithFeatures())

	orgDashboards := make([]string, 0, rowCount)
	for i := 0; i < rowCount; i++ {
		orgDashboards = append(orgDashboards, insertSharingRow(t, store, orgID, i))
	}
	otherDashboard := insertSharingRow(t, store, otherOrg, 100)

	logger := captureEngineSQL(sqlStore)

	t.Run("each page loads only that page of sharing rows", func(t *testing.T) {
		for _, page := range []int{1, 2} {
			logger.reset()
			resp, err := store.FindAll(context.Background(), &models.PublicDashboardListQuery{
				OrgID:  orgID,
				Page:   page,
				Limit:  pageSize,
				Offset: pageSize * (page - 1),
			})
			require.NoError(t, err)

			assertSharingRowQueryBounded(t, logger.snapshot(), pageSize)
			require.LessOrEqual(t, len(resp.PublicDashboards), pageSize)
			require.NotEmpty(t, resp.PublicDashboards)
			require.Equal(t, len(resp.PublicDashboards), sharingTokensLoaded(resp.PublicDashboards))
			for _, row := range resp.PublicDashboards {
				require.NotEqual(t, otherDashboard, row.DashboardUid)
				require.Contains(t, orgDashboards, row.DashboardUid)
			}
			if page == 1 {
				first := resp.PublicDashboards[0].DashboardUid
				logger.reset()
				second, err := store.FindAll(context.Background(), &models.PublicDashboardListQuery{
					OrgID:  orgID,
					Page:   2,
					Limit:  pageSize,
					Offset: pageSize,
				})
				require.NoError(t, err)
				assertSharingRowQueryBounded(t, logger.snapshot(), pageSize)
				require.Len(t, second.PublicDashboards, pageSize)
				require.NotEqual(t, first, second.PublicDashboards[0].DashboardUid)
			}
		}
	})

	t.Run("requested limit above the cap is clamped in the query", func(t *testing.T) {
		logger.reset()
		resp, err := store.FindAll(context.Background(), &models.PublicDashboardListQuery{
			OrgID:  orgID,
			Page:   1,
			Limit:  hugeLimit,
			Offset: 0,
		})
		require.NoError(t, err)
		assertSharingRowQueryBounded(t, logger.snapshot(), maxPublicDashboardListPageSize)
		require.LessOrEqual(t, len(resp.PublicDashboards), maxPublicDashboardListPageSize)
		require.LessOrEqual(t, sharingTokensLoaded(resp.PublicDashboards), maxPublicDashboardListPageSize)
	})
}

func insertSharingRow(t *testing.T, store *PublicDashboardStoreImpl, orgID int64, n int) string {
	t.Helper()
	dashboardUID := "dash-uid-" + strconv.Itoa(int(orgID)) + "-" + strconv.Itoa(n)
	_, err := store.Create(context.Background(), models.SavePublicDashboardCommand{
		PublicDashboard: models.PublicDashboard{
			Uid:          "pub-uid-" + strconv.Itoa(int(orgID)) + "-" + strconv.Itoa(n),
			DashboardUid: dashboardUID,
			OrgId:        orgID,
			// Obvious placeholder. The test never prints it.
			AccessToken:  "placeholder-token-" + strconv.Itoa(int(orgID)) + "-" + strconv.Itoa(n),
			CreatedBy:    1,
			CreatedAt:    time.Unix(1_700_000_000, 0).UTC().Add(time.Duration(n) * time.Second),
			IsEnabled:    true,
			TimeSettings: &models.TimeSettings{},
			Share:        models.PublicShareType,
		},
	})
	require.NoError(t, err)
	return dashboardUID
}

func sharingTokensLoaded(rows []*models.PublicDashboardListResponse) int {
	n := 0
	for _, row := range rows {
		if row.AccessToken != "" {
			n++
		}
	}
	return n
}

func assertSharingRowQueryBounded(t *testing.T, queries []capturedSQL, maxRows int) {
	t.Helper()
	var rowQueries []capturedSQL
	for _, q := range queries {
		if isDashboardPublicRowQuery(q.SQL) {
			rowQueries = append(rowQueries, q)
		}
	}
	require.NotEmptyf(t, rowQueries, "list did not query dashboard_public; captured %s", describeSQL(queries))
	for _, q := range rowQueries {
		limit, ok := sqlRowLimit(q.SQL, q.Args)
		require.Truef(t, ok, "sharing-row query has no LIMIT or FETCH bound: %s", q.SQL)
		require.Greaterf(t, limit, 0, "sharing-row query limit must be positive: %s", q.SQL)
		require.LessOrEqualf(t, limit, maxRows, "sharing-row query loads %d rows, bound is %d: %s", limit, maxRows, q.SQL)
	}
}

func isDashboardPublicRowQuery(sql string) bool {
	normalized := strings.ToLower(strings.Join(strings.Fields(sql), " "))
	if !strings.Contains(normalized, "dashboard_public") {
		return false
	}
	// A count does not materialize sharing rows or their access tokens.
	if strings.Contains(normalized, "count(") && !strings.Contains(normalized, "access_token") {
		return false
	}
	return true
}

var (
	commaLimitClause = regexp.MustCompile(`(?i)\blimit\s+(\d+|\?)\s*,\s*(\d+|\?)`)
	limitClause      = regexp.MustCompile(`(?i)\blimit\s+(\d+|\?)`)
	fetchClause      = regexp.MustCompile(`(?i)\bfetch\s+(?:first|next)\s+(\d+|\?)\s+rows\b`)
)

func sqlRowLimit(sql string, args []any) (int, bool) {
	normalized := strings.Join(strings.Fields(sql), " ")
	if m := commaLimitClause.FindStringSubmatchIndex(normalized); m != nil {
		return placeholderValue(normalized, m[4], m[5], args)
	}
	if m := limitClause.FindStringSubmatchIndex(normalized); m != nil {
		return placeholderValue(normalized, m[2], m[3], args)
	}
	if m := fetchClause.FindStringSubmatchIndex(normalized); m != nil {
		return placeholderValue(normalized, m[2], m[3], args)
	}
	return 0, false
}

func placeholderValue(sql string, start, end int, args []any) (int, bool) {
	token := sql[start:end]
	if token != "?" {
		n, err := strconv.Atoi(token)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	idx := strings.Count(sql[:start], "?")
	if idx >= len(args) {
		return 0, false
	}
	return asInt(args[idx])
}

func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int8:
		return int(n), true
	case int16:
		return int(n), true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	case uint:
		return int(n), true
	case uint8:
		return int(n), true
	case uint16:
		return int(n), true
	case uint32:
		return int(n), true
	case uint64:
		return int(n), true
	default:
		return 0, false
	}
}

func describeSQL(queries []capturedSQL) string {
	parts := make([]string, 0, len(queries))
	for _, q := range queries {
		parts = append(parts, strings.Join(strings.Fields(q.SQL), " "))
	}
	return strings.Join(parts, " | ")
}

type capturedSQL struct {
	SQL  string
	Args []any
}

type sqlCapture struct {
	mu      sync.Mutex
	queries []capturedSQL
	show    bool
}

func captureEngineSQL(store *sqlstore.SQLStore) *sqlCapture {
	capture := &sqlCapture{show: true}
	engine := store.GetEngine()
	engine.SetLogger(capture)
	engine.ShowSQL(true)
	return capture
}

func (c *sqlCapture) reset() {
	c.mu.Lock()
	c.queries = nil
	c.mu.Unlock()
}

func (c *sqlCapture) snapshot() []capturedSQL {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]capturedSQL, len(c.queries))
	copy(out, c.queries)
	return out
}

func (c *sqlCapture) record(format string, v ...any) {
	if !strings.Contains(format, "[SQL]") || len(v) == 0 {
		return
	}
	sqlText, ok := v[0].(string)
	if !ok {
		return
	}
	var args []any
	if len(v) > 1 {
		switch typed := v[1].(type) {
		case []any:
			args = typed
		default:
			args = []any{v[1]}
		}
	}
	c.mu.Lock()
	c.queries = append(c.queries, capturedSQL{SQL: sqlText, Args: args})
	c.mu.Unlock()
}

func (c *sqlCapture) Debug(v ...any)                 {}
func (c *sqlCapture) Debugf(format string, v ...any) {}
func (c *sqlCapture) Error(v ...any)                 {}
func (c *sqlCapture) Errorf(format string, v ...any) {}
func (c *sqlCapture) Info(v ...any)                  {}
func (c *sqlCapture) Infof(format string, v ...any)  { c.record(format, v...) }
func (c *sqlCapture) Warn(v ...any)                  {}
func (c *sqlCapture) Warnf(format string, v ...any)  {}
func (c *sqlCapture) Level() core.LogLevel           { return core.LOG_INFO }
func (c *sqlCapture) SetLevel(core.LogLevel)         {}
func (c *sqlCapture) ShowSQL(show ...bool) {
	if len(show) == 0 {
		c.show = true
		return
	}
	c.show = show[0]
}
func (c *sqlCapture) IsShowSQL() bool { return c.show }
