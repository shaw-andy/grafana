package queryhistory

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web"
)

// maxQueryHistoryPageSize is the most rows one search may load.
// Legacy dashboard search uses the same ceiling (pkg/api/search.go).
// A smaller positive ceiling also satisfies these tests.
const maxQueryHistoryPageSize = 5000

// maxStoredQueryHistoryTextBytes is the most text one create or comment update may persist.
// web.Bind allows a 100 MiB JSON body. Stored query history text has to stay far below that.
// A smaller positive ceiling also satisfies these tests.
const maxStoredQueryHistoryTextBytes = 1 << 20

func TestIntegrationQueryHistorySearchLimitIsBounded(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	// One past the ceiling, plus a newer row whose query text must be loaded with the page.
	const bulkRows = maxQueryHistoryPageSize + 1
	const storedRows = bulkRows + 1

	assertBounded := func(t *testing.T, sc scenarioContext) {
		t.Helper()

		now := time.Now().Unix()
		insertQueryHistoryRows(t, sc, "b", bulkRows, now-30, simplejson.NewFromAny(map[string]any{"expr": "row"}))
		insertQueryHistoryRows(t, sc, "m", 1, now-1, simplejson.NewFromAny(map[string]any{"expr": "MARKER"}))
		require.Equal(t, int64(storedRows), countQueryHistory(t, sc.sqlStore))

		// Attack path: GET /api/query-history?limit=2147483647
		status, body, raw := searchAsCaller(t, sc, url.Values{
			"limit": {"2147483647"},
		})
		assertSearchPageBounded(t, status, body, raw, storedRows)
		if status == http.StatusOK {
			require.Contains(t, raw, "MARKER", "the page must include saved query text, not only row ids")
		}
		require.Equal(t, int64(storedRows), countQueryHistory(t, sc.sqlStore), "search must not delete rows")
	}

	testScenario(t, "editor limit=2147483647 must not load every matching row", false, false, assertBounded)
	testScenario(t, "viewer with datasources explore limit=2147483647 must not load every matching row", true, true, assertBounded)

	testScenario(t, "viewer without datasources explore is unauthorized", true, false,
		func(t *testing.T, sc scenarioContext) {
			status, _, _ := searchAsCaller(t, sc, url.Values{"limit": {"2147483647"}})
			require.Equal(t, http.StatusUnauthorized, status)
		})

	testScenario(t, "limit within the ceiling still returns a page", false, false,
		func(t *testing.T, sc scenarioContext) {
			insertQueryHistoryRows(t, sc, "s", 3, time.Now().Unix()-1, simplejson.NewFromAny(map[string]any{"expr": "small"}))
			status, body, _ := searchAsCaller(t, sc, url.Values{"limit": {"2"}})
			require.Equal(t, http.StatusOK, status)
			require.Equal(t, 3, body.Result.TotalCount)
			require.LessOrEqual(t, body.Result.PerPage, maxQueryHistoryPageSize)
			require.Equal(t, min(2, body.Result.PerPage), len(body.Result.QueryHistory))
			require.Equal(t, int64(3), countQueryHistory(t, sc.sqlStore))
		})
}

func TestIntegrationQueryHistorySearchOffsetCannotOverflow(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	// limit*(page-1) is computed in int. These two values wrap to the minimum
	// int. On the default SQLite database a negative OFFSET is ignored, so the
	// uncapped LIMIT still loads every matching row.
	negativeLimit := strconv.FormatInt(int64(math.MaxInt/2+1), 10)
	const bulkRows = maxQueryHistoryPageSize + 1

	testScenario(t, "editor offset wrap must not load every row", false, false,
		func(t *testing.T, sc scenarioContext) {
			insertQueryHistoryRows(t, sc, "n", bulkRows, time.Now().Unix()-1, simplejson.NewFromAny(map[string]any{"expr": "offset"}))
			before := countQueryHistory(t, sc.sqlStore)
			status, body, raw := searchAsCaller(t, sc, url.Values{
				"limit": {negativeLimit},
				"page":  {"3"},
			})
			require.Equal(t, before, countQueryHistory(t, sc.sqlStore), "a refused search must not change stored rows")
			assertOffsetSafe(t, status, body, raw, int(before))
		})

	// page is the largest integer QueryInt accepts. limit*(page-1) still
	// overflows after limit is capped to maxQueryHistoryPageSize, so a fix
	// that only caps limit does not satisfy this test.
	maxPage := strconv.FormatInt(int64(math.MaxInt), 10)
	testScenario(t, "editor max page must not wrap after the limit is capped", false, false,
		func(t *testing.T, sc scenarioContext) {
			insertQueryHistoryRows(t, sc, "p", 3, time.Now().Unix()-1, simplejson.NewFromAny(map[string]any{"expr": "page"}))
			status, body, raw := searchAsCaller(t, sc, url.Values{
				"limit": {"2147483647"},
				"page":  {maxPage},
			})
			assertOffsetSafe(t, status, body, raw, 3)
		})

	testScenario(t, "viewer with datasources explore max page must not wrap", true, true,
		func(t *testing.T, sc scenarioContext) {
			insertQueryHistoryRows(t, sc, "p", 3, time.Now().Unix()-1, simplejson.NewFromAny(map[string]any{"expr": "page"}))
			status, body, raw := searchAsCaller(t, sc, url.Values{
				"limit": {"2147483647"},
				"page":  {maxPage},
			})
			assertOffsetSafe(t, status, body, raw, 3)
		})
}

func TestIntegrationQueryHistoryCreateRejectsOversizedQueries(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	testScenario(t, "editor cannot store a queries document above the cap", false, false,
		func(t *testing.T, sc scenarioContext) {
			before := countQueryHistory(t, sc.sqlStore)
			status, raw := createAsCaller(t, sc, oversizedQueriesBody())
			require.NotEqual(t, http.StatusOK, status)
			require.Contains(t, []int{http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity}, status, "body: %s", raw)
			require.Equal(t, before, countQueryHistory(t, sc.sqlStore), "refusing an oversized queries document must not insert a row")
			require.NotContains(t, raw, "OVERSIZE")
		})

	testScenario(t, "viewer with datasources explore cannot store a queries document above the cap", true, true,
		func(t *testing.T, sc scenarioContext) {
			before := countQueryHistory(t, sc.sqlStore)
			status, raw := createAsCaller(t, sc, oversizedQueriesBody())
			require.NotEqual(t, http.StatusOK, status)
			require.Contains(t, []int{http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity}, status, "body: %s", raw)
			require.Equal(t, before, countQueryHistory(t, sc.sqlStore))
		})

	testScenario(t, "a small queries document is still stored", false, false,
		func(t *testing.T, sc scenarioContext) {
			status, raw := createAsCaller(t, sc, `{"datasourceUid":"NCzh67i","queries":{"expr":"small"}}`)
			require.Equal(t, http.StatusOK, status, "body: %s", raw)
			require.Equal(t, int64(1), countQueryHistory(t, sc.sqlStore))
		})
}

func TestIntegrationQueryHistoryPatchRejectsOversizedComment(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	testScenario(t, "editor cannot replace a comment with text above the cap", false, false,
		func(t *testing.T, sc scenarioContext) {
			status, raw := createAsCaller(t, sc, `{"datasourceUid":"NCzh67i","queries":{"expr":"small"}}`)
			require.Equal(t, http.StatusOK, status, "body: %s", raw)
			var created QueryHistoryResponse
			require.NoError(t, json.Unmarshal([]byte(raw), &created))

			before := countQueryHistory(t, sc.sqlStore)
			comment := strings.Repeat("C", maxStoredQueryHistoryTextBytes+1)
			status, raw = patchCommentAsCaller(t, sc, created.Result.UID, comment)
			require.NotEqual(t, http.StatusOK, status)
			require.Contains(t, []int{http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity}, status, "body: %s", raw)
			require.Equal(t, before, countQueryHistory(t, sc.sqlStore))
			require.Empty(t, storedComment(t, sc.sqlStore, created.Result.UID))
			require.NotContains(t, raw, comment[:64])
		})
}

func assertSearchPageBounded(t *testing.T, status int, body QueryHistorySearchResponse, raw string, storedRows int) {
	t.Helper()

	switch status {
	case http.StatusOK:
		require.LessOrEqualf(t, len(body.Result.QueryHistory), maxQueryHistoryPageSize,
			"search loaded %d rows into the response (perPage %d, totalCount %d)",
			len(body.Result.QueryHistory), body.Result.PerPage, body.Result.TotalCount)
		require.Positive(t, body.Result.PerPage)
		require.LessOrEqual(t, body.Result.PerPage, maxQueryHistoryPageSize)
		require.Equal(t, storedRows, body.Result.TotalCount)
		require.Equal(t, min(storedRows, body.Result.PerPage), len(body.Result.QueryHistory))
		require.NotEmpty(t, body.Result.QueryHistory[0].Queries)
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		require.NotContains(t, raw, "MARKER")
		require.NotContains(t, raw, `"queryHistory"`)
	default:
		t.Fatalf("search status = %d, want 200 with a bounded page or 400/422 before loading rows; body: %s", status, raw[:min(len(raw), 512)])
	}
}

func assertOffsetSafe(t *testing.T, status int, body QueryHistorySearchResponse, raw string, storedRows int) {
	t.Helper()

	switch status {
	case http.StatusOK:
		require.LessOrEqualf(t, len(body.Result.QueryHistory), maxQueryHistoryPageSize,
			"search loaded %d rows (perPage %d, page %d, totalCount %d)",
			len(body.Result.QueryHistory), body.Result.PerPage, body.Result.Page, body.Result.TotalCount)
		require.Positive(t, body.Result.PerPage)
		require.LessOrEqual(t, body.Result.PerPage, maxQueryHistoryPageSize)
		require.Positive(t, body.Result.Page)
		require.Equal(t, storedRows, body.Result.TotalCount)
		require.LessOrEqual(t, len(body.Result.QueryHistory), body.Result.PerPage)
		// The offset is limit*(page-1). The reported page and page size are what
		// the handler applied, and that product has to fit in a non-negative int.
		// Clamping only the limit still overflows once page is large enough.
		require.LessOrEqual(t, body.Result.Page-1, math.MaxInt/body.Result.PerPage)
		offset := body.Result.PerPage * (body.Result.Page - 1)
		require.GreaterOrEqual(t, offset, 0)
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		require.NotContains(t, raw, "offset")
	default:
		t.Fatalf("search status = %d, want 200 with a non-wrapping page or 400/422; body: %s", status, raw[:min(len(raw), 512)])
	}
}

func searchAsCaller(t *testing.T, sc scenarioContext, query url.Values) (int, QueryHistorySearchResponse, string) {
	t.Helper()

	sc.reqContext.Req.Form = query
	handler := sc.service.permissionsMiddleware(sc.service.searchHandler, "Failed to get query history")
	resp := handler(sc.reqContext)
	raw := string(resp.Body())
	var body QueryHistorySearchResponse
	if resp.Status() == http.StatusOK {
		require.NoError(t, json.Unmarshal(resp.Body(), &body), raw[:min(len(raw), 512)])
	}
	return resp.Status(), body, raw
}

func createAsCaller(t *testing.T, sc scenarioContext, body string) (int, string) {
	t.Helper()

	sc.reqContext.Req.Body = http.NoBody
	sc.reqContext.Req.Body = ioNopCloser(strings.NewReader(body))
	sc.reqContext.Req.ContentLength = int64(len(body))
	sc.reqContext.Req.Header.Set("Content-Type", "application/json")
	handler := sc.service.permissionsMiddleware(sc.service.createHandler, "Failed to create query history")
	resp := handler(sc.reqContext)
	return resp.Status(), string(resp.Body())
}

func patchCommentAsCaller(t *testing.T, sc scenarioContext, uid string, comment string) (int, string) {
	t.Helper()

	payload, err := json.Marshal(PatchQueryCommentInQueryHistoryCommand{Comment: comment})
	require.NoError(t, err)
	sc.ctx.Req = web.SetURLParams(sc.ctx.Req, map[string]string{":uid": uid})
	sc.reqContext.Req.Body = ioNopCloser(strings.NewReader(string(payload)))
	sc.reqContext.Req.ContentLength = int64(len(payload))
	sc.reqContext.Req.Header.Set("Content-Type", "application/json")
	handler := sc.service.permissionsMiddleware(sc.service.patchCommentHandler, "Failed to update comment of query in query history")
	resp := handler(sc.reqContext)
	return resp.Status(), string(resp.Body())
}

func oversizedQueriesBody() string {
	// The queries value itself is past the cap. The wrapper keys make the HTTP
	// body a little larger, still far under the 100 MiB bind limit.
	var b strings.Builder
	b.Grow(maxStoredQueryHistoryTextBytes + 64)
	b.WriteString(`{"datasourceUid":"NCzh67i","queries":{"expr":"OVERSIZE`)
	b.WriteString(strings.Repeat("Q", maxStoredQueryHistoryTextBytes))
	b.WriteString(`"}}`)
	return b.String()
}

func insertQueryHistoryRows(t *testing.T, sc scenarioContext, prefix string, n int, createdAt int64, queries *simplejson.Json) {
	t.Helper()

	const batchSize = 100
	err := sc.sqlStore.WithDbSession(context.Background(), func(session *db.Session) error {
		batch := make([]*QueryHistory, 0, batchSize)
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			_, err := session.Insert(&batch)
			batch = batch[:0]
			return err
		}
		for i := 0; i < n; i++ {
			batch = append(batch, &QueryHistory{
				OrgID:         testOrgID,
				UID:           fmt.Sprintf("%s%010d", prefix, i),
				DatasourceUID: testDsUID1,
				CreatedBy:     testUserID,
				CreatedAt:     createdAt,
				Comment:       "",
				Queries:       queries,
			})
			if len(batch) == batchSize {
				if err := flush(); err != nil {
					return err
				}
			}
		}
		return flush()
	})
	require.NoError(t, err)
}

func countQueryHistory(t *testing.T, store db.DB) int64 {
	t.Helper()

	var n int64
	err := store.WithDbSession(context.Background(), func(session *db.Session) error {
		count, err := session.Table("query_history").Count()
		n = count
		return err
	})
	require.NoError(t, err)
	return n
}

func storedComment(t *testing.T, store db.DB, uid string) string {
	t.Helper()

	var row QueryHistory
	err := store.WithDbSession(context.Background(), func(session *db.Session) error {
		_, err := session.Table("query_history").Where("uid = ?", uid).Get(&row)
		return err
	})
	require.NoError(t, err)
	return row.Comment
}

type stringReadCloser struct {
	*strings.Reader
}

func (s stringReadCloser) Close() error { return nil }

func ioNopCloser(r *strings.Reader) stringReadCloser {
	return stringReadCloser{Reader: r}
}
