package common

import (
	"net/url"
	"strconv"

	"k8s.io/apimachinery/pkg/apis/meta/internalversion"

	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

// ExtendInexactSearchTotal makes TotalHits safe to page on for clients that
// only read the total. A total that is not exact counts only what the backend
// authorized before it stopped scanning, so after a full page it can equal
// offset+limit while more results exist. Reporting one past the page keeps the
// next page reachable; it depends only on rows the caller was allowed to see.
func ExtendInexactSearchTotal(resp *resourcepb.ResourceSearchResponse, offset, limit int64) {
	if resp == nil || resp.GetTotalHitsExact() || limit <= 0 {
		return
	}
	rows := int64(len(resp.GetRows()) + len(resp.GetResults().GetRows()))
	if rows >= limit {
		resp.TotalHits = max(resp.TotalHits, offset+rows+1)
	}
}

type Pagination struct {
	Limit    int64
	Continue int64
}

func PaginationFromListOptions(options *internalversion.ListOptions) Pagination {
	limit := options.Limit
	if limit < 1 {
		limit = DefaultListLimit
	}

	if limit > MaxListLimit {
		limit = MaxListLimit
	}

	return Pagination{
		Limit:    limit,
		Continue: parseIntWithFallback(options.Continue, 0, 0),
	}
}

func PaginationFromListQuery(query url.Values) Pagination {
	return Pagination{
		Limit:    parseIntWithFallback(query.Get("limit"), 1, DefaultListLimit),
		Continue: parseIntWithFallback(query.Get("continue"), 0, 0),
	}
}

func parseIntWithFallback(original string, min int64, fallback int64) int64 {
	if original == "" {
		return fallback
	}
	v, err := strconv.ParseInt(original, 10, 64)
	if err != nil {
		return fallback
	}

	if v < min {
		return fallback
	}

	return v
}
