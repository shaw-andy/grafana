package display

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	authlib "github.com/grafana/authlib/types"
	iam "github.com/grafana/grafana/pkg/apis/iam/v0alpha1"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/storage/unified/search/builders"
)

func TestBuildSearchJobsRequestsFieldValues(t *testing.T) {
	provider := &SearchDisplayProvider{}
	jobs := provider.buildSearchJobs(authlib.NamespaceInfo{Value: "stacks-1"}, dispKeys{
		uids: []string{"user-1"},
		ids:  []int64{42},
	})

	require.Len(t, jobs, 4)
	for _, job := range jobs {
		require.Equal(t, resourcepb.ResourceSearchRequest_FIELD_VALUES, job.req.ResultFormat)
		switch job.req.Options.Key.Resource {
		case "users":
			require.Equal(t, []string{
				resource.SEARCH_FIELD_TITLE,
				builders.USER_EMAIL,
				builders.USER_LOGIN,
				resource.SEARCH_FIELD_LEGACY_ID,
			}, job.req.Fields)
		case "serviceaccounts":
			require.Equal(t, []string{
				resource.SEARCH_FIELD_TITLE,
				resource.SEARCH_FIELD_LEGACY_ID,
			}, job.req.Fields)
		default:
			t.Fatalf("unexpected resource %q", job.req.Options.Key.Resource)
		}
	}
}

func TestAppendDisplayRowsDecodesBothResultFormats(t *testing.T) {
	legacyID := make([]byte, 8)
	binary.BigEndian.PutUint64(legacyID, 42)
	tableResponse := &resourcepb.ResourceSearchResponse{
		Results: &resourcepb.ResourceTable{
			Columns: []*resourcepb.ResourceTableColumnDefinition{
				{Name: resource.SEARCH_FIELD_TITLE},
				{Name: builders.USER_EMAIL},
				{Name: builders.USER_LOGIN},
				{Name: resource.SEARCH_FIELD_LEGACY_ID},
			},
			Rows: []*resourcepb.ResourceTableRow{{
				Key:   &resourcepb.ResourceKey{Name: "user-1"},
				Cells: [][]byte{[]byte(""), []byte("user@example.com"), []byte("login"), legacyID},
			}},
		},
	}
	typedResponse := &resourcepb.ResourceSearchResponse{
		ResultFormat: resourcepb.ResourceSearchRequest_FIELD_VALUES,
		Fields: []*resourcepb.ResourceSearchField{
			{Name: resource.SEARCH_FIELD_TITLE, Type: resourcepb.ResourceSearchField_STRING},
			{Name: builders.USER_EMAIL, Type: resourcepb.ResourceSearchField_STRING},
			{Name: builders.USER_LOGIN, Type: resourcepb.ResourceSearchField_STRING},
			{Name: resource.SEARCH_FIELD_LEGACY_ID, Type: resourcepb.ResourceSearchField_INT64},
		},
		Rows: []*resourcepb.ResourceSearchRow{{
			Key: &resourcepb.ResourceKey{Name: "user-1"},
			Values: []*resourcepb.ResourceSearchValue{
				{FieldIndex: 0, StringValues: []string{""}},
				{FieldIndex: 1, StringValues: []string{"user@example.com"}},
				{FieldIndex: 2, StringValues: []string{"login"}},
				{FieldIndex: 3, Int64Values: []int64{42}},
			},
		}},
	}

	decode := func(response *resourcepb.ResourceSearchResponse) (*iam.DisplayList, map[string]struct{}, map[int64]struct{}) {
		list := &iam.DisplayList{}
		foundUIDs := map[string]struct{}{}
		foundIDs := map[int64]struct{}{}
		require.NoError(t, appendDisplayRows(list, response, authlib.TypeUser, allowAll, foundUIDs, foundIDs))
		return list, foundUIDs, foundIDs
	}

	tableList, tableUIDs, tableIDs := decode(tableResponse)
	typedList, typedUIDs, typedIDs := decode(typedResponse)
	require.Equal(t, tableList, typedList)
	require.Equal(t, tableUIDs, typedUIDs)
	require.Equal(t, tableIDs, typedIDs)
	require.Equal(t, "login", typedList.Items[0].DisplayName)
	require.Equal(t, int64(42), typedList.Items[0].InternalID)
}

func TestAppendDisplayRowsAppliesFilter(t *testing.T) {
	response := &resourcepb.ResourceSearchResponse{
		ResultFormat: resourcepb.ResourceSearchRequest_FIELD_VALUES,
		Fields: []*resourcepb.ResourceSearchField{
			{Name: resource.SEARCH_FIELD_TITLE, Type: resourcepb.ResourceSearchField_STRING},
			{Name: builders.USER_LOGIN, Type: resourcepb.ResourceSearchField_STRING},
			{Name: resource.SEARCH_FIELD_LEGACY_ID, Type: resourcepb.ResourceSearchField_INT64},
		},
		Rows: []*resourcepb.ResourceSearchRow{
			{
				Key: &resourcepb.ResourceKey{Name: "user-1"},
				Values: []*resourcepb.ResourceSearchValue{
					{FieldIndex: 0, StringValues: []string{"Allowed"}},
					{FieldIndex: 1, StringValues: []string{"allowed"}},
					{FieldIndex: 2, Int64Values: []int64{1}},
				},
			},
			{
				Key: &resourcepb.ResourceKey{Name: "user-2"},
				Values: []*resourcepb.ResourceSearchValue{
					{FieldIndex: 0, StringValues: []string{"Denied"}},
					{FieldIndex: 1, StringValues: []string{"denied"}},
					{FieldIndex: 2, Int64Values: []int64{2}},
				},
			},
		},
	}

	var seen []Member
	list := &iam.DisplayList{}
	foundUIDs := map[string]struct{}{}
	foundIDs := map[int64]struct{}{}
	require.NoError(t, appendDisplayRows(list, response, authlib.TypeUser, func(m Member) bool {
		seen = append(seen, m)
		return m.Login == "allowed"
	}, foundUIDs, foundIDs))

	require.Equal(t, []Member{
		{Type: authlib.TypeUser, UID: "user-1", ID: 1, Login: "allowed"},
		{Type: authlib.TypeUser, UID: "user-2", ID: 2, Login: "denied"},
	}, seen)
	require.Len(t, list.Items, 1)
	require.Equal(t, "user-1", list.Items[0].Identity.Name)
	require.Equal(t, map[string]struct{}{"user-1": {}}, foundUIDs)
	require.Equal(t, map[int64]struct{}{1: {}}, foundIDs)
}
