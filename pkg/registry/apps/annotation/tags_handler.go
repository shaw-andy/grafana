package annotation

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"time"

	authtypes "github.com/grafana/authlib/types"
	"github.com/grafana/grafana-app-sdk/app"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	annotationV0 "github.com/grafana/grafana/apps/annotation/pkg/apis/annotation/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/infra/log"
)

// authorizedTagProvider exposes the counts of a DashboardTagCounter only for the
// dashboards, and organization annotations, the requester can read.
type authorizedTagProvider struct {
	counter        DashboardTagCounter
	tracer         trace.Tracer
	accessClient   authtypes.AccessClient
	folderResolver DashboardFolderResolver
}

func newAuthorizedTagProvider(counter DashboardTagCounter, tracer trace.Tracer, accessClient authtypes.AccessClient, folderResolver DashboardFolderResolver) *authorizedTagProvider {
	return &authorizedTagProvider{
		counter:        counter,
		tracer:         tracer,
		accessClient:   accessClient,
		folderResolver: folderResolver,
	}
}

func (p *authorizedTagProvider) ListTags(ctx context.Context, namespace string, opts TagListOptions) ([]Tag, error) {
	// The limit can only be applied once unreadable dashboards are dropped.
	rows, err := p.counter.ListDashboardTags(ctx, namespace, TagListOptions{Prefix: opts.Prefix, Contains: opts.Contains})
	if err != nil {
		return nil, err
	}

	dashboardIndex := make(map[string]int)
	var probes []annotationV0.Annotation
	for _, row := range rows {
		if _, ok := dashboardIndex[row.DashboardUID]; ok {
			continue
		}
		dashboardIndex[row.DashboardUID] = len(probes)
		var probe annotationV0.Annotation
		if row.DashboardUID != "" {
			probe.Spec.DashboardUID = &row.DashboardUID
		}
		probes = append(probes, probe)
	}

	allowed, err := canAccessAnnotations(ctx, p.tracer, p.accessClient, p.folderResolver, namespace, probes, utils.VerbList)
	if err != nil {
		return nil, err
	}

	counts := make(map[string]int64)
	for _, row := range rows {
		if allowed[dashboardIndex[row.DashboardUID]] {
			counts[row.Name] += row.Count
		}
	}

	tags := make([]Tag, 0, len(counts))
	for name, count := range counts {
		tags = append(tags, Tag{Name: name, Count: count})
	}
	slices.SortFunc(tags, func(a, b Tag) int {
		return cmp.Compare(a.Name, b.Name)
	})
	if opts.Limit > 0 && len(tags) > opts.Limit {
		tags = tags[:opts.Limit]
	}
	return tags, nil
}

type TagResponse struct {
	Tags []TagItem `json:"tags"`
}

type TagItem struct {
	Tag   string `json:"tag"`
	Count int64  `json:"count"`
}

func newTagsHandler(
	tagProvider TagProvider,
	tracer trace.Tracer,
	accessClient authtypes.AccessClient,
	metrics *Metrics,
	logger log.Logger,
) func(ctx context.Context, writer app.CustomRouteResponseWriter, request *app.CustomRouteRequest) error {
	return func(ctx context.Context, writer app.CustomRouteResponseWriter, request *app.CustomRouteRequest) (err error) {
		namespace := request.ResourceIdentifier.Namespace

		ctx, span := tracer.Start(ctx, "annotation.k8s.tags", trace.WithAttributes(
			attribute.String("namespace", namespace),
		))
		defer span.End()
		start := time.Now()
		defer func() { observe(ctx, logger, metrics.RequestDuration, "tags", start, err) }()

		// Tags are an org-wide aggregate, so gate the request on org-level
		// annotation read before exposing any tag metadata.
		if err = authorizeReadOrganizationAnnotations(ctx, accessClient, namespace); err != nil {
			return err
		}

		opts := TagListOptions{}
		queryParams := request.URL.Query()

		prefix := queryParams.Get("prefix")
		contains := queryParams.Get("contains")
		if prefix != "" && contains != "" {
			return apierrors.NewBadRequest(fmt.Sprintf("%v: prefix and contains are mutually exclusive", ErrInvalidInput))
		}
		opts.Prefix = prefix
		opts.Contains = contains

		opts.Limit = 100 // default limit
		if v := queryParams.Get("limit"); v != "" {
			if limit, err := strconv.Atoi(v); err == nil && limit > 0 {
				opts.Limit = limit
			}
		}

		tags, err := tagProvider.ListTags(ctx, namespace, opts)
		if err != nil {
			return err
		}
		items := make([]TagItem, len(tags))
		for i, tag := range tags {
			items[i] = TagItem{
				Tag:   tag.Name,
				Count: tag.Count,
			}
		}
		span.SetAttributes(attribute.Int("item_count", len(items)))

		response := TagResponse{
			Tags: items,
		}

		return json.NewEncoder(writer).Encode(response)
	}
}
