package search_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/selection"

	authlib "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	dashboardsearch "github.com/grafana/grafana/pkg/services/dashboards/service/search"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/storage/unified/search"
	"github.com/grafana/grafana/pkg/storage/unified/search/builders"
)

// Post-rank authorization ranks matches before it checks permissions, then
// stops once the page is full. These tests pin the total that scan is allowed
// to report: the authorized hits it actually observed. The pre-authorization
// Bleve match count includes dashboards and folders the caller cannot open.

const (
	visibleFolder = "visible"
	secretFolder  = "secret"
	visibleName   = "team-overview"
	hiddenName    = "acquisition-plan"
	visibleTitle  = "Team Overview"
	hiddenTitle   = "Acquisition Plan"
)

func disclosureDoc(name, title, folder string) *resource.BulkIndexItem {
	return &resource.BulkIndexItem{
		Action: resource.ActionIndex,
		Doc: &resource.IndexableDocument{
			RV:    1,
			Name:  name,
			Title: title,
			Key: &resourcepb.ResourceKey{
				Name:      name,
				Namespace: postRankKey.Namespace,
				Group:     postRankKey.Group,
				Resource:  postRankKey.Resource,
			},
			Folder: folder,
			Tags:   []string{"leak"},
			Fields: map[string]any{
				builders.DASHBOARD_PANEL_TYPES: []string{"timeseries"},
				builders.DASHBOARD_DS_TYPES:    []string{"prometheus"},
			},
		},
	}
}

func indexVisibleAndHidden(t *testing.T, index resource.ResourceIndex) {
	t.Helper()
	indexDocs(t, index, []*resource.BulkIndexItem{
		disclosureDoc(visibleName, visibleTitle, visibleFolder),
		disclosureDoc(hiddenName, hiddenTitle, secretFolder),
	})
}

func viewerAccess() *countingAccessClient {
	return &countingAccessClient{allowedFolders: map[string]bool{visibleFolder: true}}
}

func titleInQuery(limit int64) *resourcepb.ResourceSearchRequest {
	q := listQuery(limit)
	q.Options.Fields = []*resourcepb.Requirement{{
		Key:      resource.SEARCH_FIELD_TITLE,
		Operator: string(selection.In),
		Values:   []string{visibleTitle, hiddenTitle},
	}}
	return q
}

// requireObservedAuthorizedTotal fails while the response reports Bleve's
// unfiltered match count. observed is how many hits this scan authorized.
func requireObservedAuthorizedTotal(t *testing.T, res *resourcepb.ResourceSearchResponse, observed, unfiltered int64) {
	t.Helper()
	require.Less(t, observed, unfiltered, "fixture must include at least one unauthorized match")
	require.Equal(t, observed, res.TotalHits, "total must count authorized hits observed on this scan, not the unfiltered match count %d", unfiltered)
	require.False(t, res.TotalHitsExact, "a scan that stopped early or did not start at the top is not an exact total")
}

func TestPostRankTotalHits_LimitOneDoesNotCountHiddenDashboards(t *testing.T) {
	index := newTestDashboardsIndexPostRank(t, 2)
	indexVisibleAndHidden(t, index)

	names, res := searchNames(t, index, viewerAccess(), titleInQuery(1))

	require.Equal(t, []string{visibleName}, names, "the hidden dashboard must not be returned")
	// Hidden title sorts first, so the scan denies it and then fills the page
	// with the visible dashboard. Stopping there used to report both matches.
	requireObservedAuthorizedTotal(t, res, 1, 2)

	parsed, err := dashboardsearch.ParseResults(res, 0)
	require.NoError(t, err)
	require.Equal(t, int64(1), parsed.TotalHits, "dashboard search copies totalHits through to the caller")
	require.Len(t, parsed.Hits, 1)
	require.Equal(t, visibleTitle, parsed.Hits[0].Title)
}

func TestPostRankTotalHits_SharedFiltersDoNotCountHiddenDashboards(t *testing.T) {
	index := newTestDashboardsIndexPostRank(t, 2)
	indexVisibleAndHidden(t, index)
	ac := viewerAccess()

	filters := map[string]*resourcepb.ResourceSearchRequest{
		"tag": func() *resourcepb.ResourceSearchRequest {
			q := listQuery(1)
			q.Options.Fields = []*resourcepb.Requirement{{
				Key: resource.SEARCH_FIELD_TAGS, Operator: string(selection.Equals), Values: []string{"leak"},
			}}
			return q
		}(),
		"folder": func() *resourcepb.ResourceSearchRequest {
			q := listQuery(1)
			q.Options.Fields = []*resourcepb.Requirement{{
				Key: resource.SEARCH_FIELD_FOLDER, Operator: string(selection.In), Values: []string{visibleFolder, secretFolder},
			}}
			return q
		}(),
		"panel type": func() *resourcepb.ResourceSearchRequest {
			q := listQuery(1)
			q.Options.Fields = []*resourcepb.Requirement{{
				Key: builders.DASHBOARD_PANEL_TYPES, Operator: string(selection.Equals), Values: []string{"timeseries"},
			}}
			return q
		}(),
		"datasource type": func() *resourcepb.ResourceSearchRequest {
			q := listQuery(1)
			q.Options.Fields = []*resourcepb.Requirement{{
				Key: builders.DASHBOARD_DS_TYPES, Operator: string(selection.Equals), Values: []string{"prometheus"},
			}}
			return q
		}(),
		"text query": func() *resourcepb.ResourceSearchRequest {
			q := listQuery(1)
			// Both titles contain a token the standard analyzer keeps.
			q.Query = "plan"
			q.QueryFields = []*resourcepb.ResourceSearchRequest_QueryField{{Name: resource.SEARCH_FIELD_TITLE, Boost: 1}}
			return q
		}(),
	}

	// The text query only matches the hidden title. Give both titles a shared
	// token for that one case without changing the title-in fixture.
	textDocs := []*resource.BulkIndexItem{
		disclosureDoc(visibleName, "Team Overview Plan", visibleFolder),
		disclosureDoc(hiddenName, hiddenTitle, secretFolder),
	}

	for name, q := range filters {
		t.Run(name, func(t *testing.T) {
			idx := index
			access := ac
			if name == "text query" {
				idx = newTestDashboardsIndexPostRank(t, 2)
				indexDocs(t, idx, textDocs)
				access = viewerAccess()
			}
			names, res := searchNames(t, idx, access, q)
			require.Equal(t, []string{visibleName}, names)
			requireObservedAuthorizedTotal(t, res, 1, 2)
		})
	}
}

func TestPostRankTotalHits_ContinueCursorDoesNotCountHiddenDashboards(t *testing.T) {
	index := newTestDashboardsIndexPostRank(t, 2)
	indexDocs(t, index, []*resource.BulkIndexItem{
		disclosureDoc(hiddenName, hiddenTitle, secretFolder),
		disclosureDoc(visibleName, visibleTitle, visibleFolder),
		disclosureDoc("zebra-board", "Zebra Board", visibleFolder),
	})
	ac := viewerAccess()

	t.Run("first page", func(t *testing.T) {
		firstNames, first := searchNames(t, index, ac, listQuery(1))
		require.Equal(t, []string{visibleName}, firstNames)
		requireObservedAuthorizedTotal(t, first, 1, 3)
	})

	t.Run("continue cursor", func(t *testing.T) {
		_, first := searchNames(t, index, ac, listQuery(1))
		next := listQuery(1)
		next.SearchAfter = first.Results.GetRows()[0].SortFields
		nextNames, second := searchNames(t, index, ac, next)
		require.Equal(t, []string{"zebra-board"}, nextNames)
		// The cursor page still sees the pre-authorization total of every match,
		// including the hidden dashboard that sorted before the cursor.
		requireObservedAuthorizedTotal(t, second, 1, 3)
	})

	t.Run("search before", func(t *testing.T) {
		// Walk backward from the last visible dashboard. The hidden dashboard
		// sorts ahead of it, so a one-row page fills with the other visible
		// dashboard and stops before that hidden match is a reason to keep counting.
		all, full := searchNames(t, index, &countingAccessClient{allowAll: true}, listQuery(10))
		require.Equal(t, []string{hiddenName, visibleName, "zebra-board"}, all)
		var zebraCursor []string
		for _, row := range full.Results.GetRows() {
			if row.Key.Name == "zebra-board" {
				zebraCursor = row.SortFields
			}
		}
		require.NotEmpty(t, zebraCursor)

		before := listQuery(1)
		before.SearchBefore = zebraCursor
		beforeNames, backward := searchNames(t, index, ac, before)
		require.Equal(t, []string{visibleName}, beforeNames)
		requireObservedAuthorizedTotal(t, backward, 1, 3)
	})
}

func TestPostRankTotalHits_CountBudgetDoesNotFallBackToUnfilteredTotal(t *testing.T) {
	// GET dashboard search forwards limit=0 as a count-only request. The scan
	// stops at MaxCandidates and used to report the unfiltered match count.
	cfg := search.PostRankAuthzConfig{MaxWindow: 4, MaxCandidates: 4}
	index := newTestDashboardsIndexPostRankWithConfig(t, 2, cfg)
	docs := make([]*resource.BulkIndexItem, 0, 10)
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		folder := secretFolder
		if name == "b" || name == "d" || name == "f" || name == "h" || name == "j" {
			folder = visibleFolder
		}
		docs = append(docs, disclosureDoc(name, name, folder))
	}
	indexDocs(t, index, docs)

	names, res := searchNames(t, index, viewerAccess(), listQuery(0))
	require.Empty(t, names)
	// Title order is a, b, c, d, ... The budget covers four hits: b and d are
	// visible, a and c are not.
	requireObservedAuthorizedTotal(t, res, 2, 10)
}

func TestPostRankTotalHits_InSearcherPathCountsOnlyAuthorized(t *testing.T) {
	// Control: with post-rank authorization off, the in-searcher wrapper
	// filters before Bleve counts, so the total is already the authorized one.
	index := newTestDashboardsIndex(t, threshold, 2, noop)
	indexVisibleAndHidden(t, index)

	names, res := searchNames(t, index, viewerAccess(), titleInQuery(1))
	require.Equal(t, []string{visibleName}, names)
	require.Equal(t, int64(1), res.TotalHits)
	require.True(t, res.TotalHitsExact)
}

func TestPostRankTotalHits_FederatedFolderDoesNotCountHiddenFolder(t *testing.T) {
	dash := newTestDashboardsIndexPostRank(t, 2)
	folders := newTestFoldersIndexPostRank(t, 2, search.PostRankAuthzConfig{})
	indexDocs(t, dash, []*resource.BulkIndexItem{
		disclosureDoc(visibleName, visibleTitle, visibleFolder),
	})
	indexDocs(t, folders, []*resource.BulkIndexItem{{
		Action: resource.ActionIndex,
		Doc: &resource.IndexableDocument{
			RV:    1,
			Name:  "secret-folder",
			Title: hiddenTitle,
			Key: &resourcepb.ResourceKey{
				Name:      "secret-folder",
				Namespace: postRankKey.Namespace,
				Group:     "folder.grafana.app",
				Resource:  "folders",
			},
			// Folder hits are authorized on the stored folder field, same as dashboards.
			Folder: secretFolder,
		},
	}})

	q := listQuery(1)
	q.Federated = []*resourcepb.ResourceKey{{
		Namespace: postRankKey.Namespace,
		Group:     "folder.grafana.app",
		Resource:  "folders",
	}}
	q.Options.Fields = []*resourcepb.Requirement{{
		Key:      resource.SEARCH_FIELD_TITLE,
		Operator: string(selection.In),
		Values:   []string{visibleTitle, hiddenTitle},
	}}

	requester := &identity.StaticRequester{Type: authlib.TypeUser, UserID: 1, Namespace: postRankKey.Namespace}
	ctx := authlib.WithAuthInfo(context.Background(), requester)
	joined, err := dash.Search(ctx, viewerAccess(), q, []resource.ResourceIndex{folders}, nil)
	require.NoError(t, err)
	require.Nil(t, joined.Error)
	require.Len(t, joined.Results.GetRows(), 1)
	require.Equal(t, visibleName, joined.Results.GetRows()[0].Key.Name)
	requireObservedAuthorizedTotal(t, joined, 1, 2)
}
