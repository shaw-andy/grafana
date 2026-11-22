package clientmiddleware

import (
	"context"

	"github.com/grafana/grafana-plugin-sdk-go/backend"

	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/services/query"
)

// NewPublicDashboardHeaderMiddleware creates a new backend.HandlerMiddleware that marks
// query requests made for a public dashboard so data sources can run them server-side.
func NewPublicDashboardHeaderMiddleware() backend.HandlerMiddleware {
	return backend.HandlerMiddlewareFunc(func(next backend.Handler) backend.Handler {
		return &PublicDashboardHeaderMiddleware{
			BaseHandler: backend.NewBaseHandler(next),
		}
	})
}

type PublicDashboardHeaderMiddleware struct {
	backend.BaseHandler
}

// applyPublicDashboardHeader sets the header only from server-side request state, and removes any
// value already on the request, so a client cannot claim to be a public dashboard query.
func applyPublicDashboardHeader(ctx context.Context, headers map[string]string) {
	delete(headers, query.HeaderFromPublicDashboard)

	reqCtx := contexthandler.FromContext(ctx)
	if reqCtx == nil || !reqCtx.IsPublicDashboardView() {
		return
	}
	headers[query.HeaderFromPublicDashboard] = "true"
}

func (m *PublicDashboardHeaderMiddleware) QueryData(ctx context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
	if req != nil {
		if req.Headers == nil {
			req.Headers = map[string]string{}
		}
		applyPublicDashboardHeader(ctx, req.Headers)
	}
	return m.BaseHandler.QueryData(ctx, req)
}

func (m *PublicDashboardHeaderMiddleware) QueryChunkedData(ctx context.Context, req *backend.QueryChunkedDataRequest, w backend.ChunkedDataWriter) error {
	if req != nil {
		if req.Headers == nil {
			req.Headers = map[string]string{}
		}
		applyPublicDashboardHeader(ctx, req.Headers)
	}
	return m.BaseHandler.QueryChunkedData(ctx, req, w)
}
