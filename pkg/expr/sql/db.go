//go:build !arm

package sql

import (
	"context"
	"errors"
	"fmt"
	"time"

	sqle "github.com/dolthub/go-mysql-server"
	mysql "github.com/dolthub/go-mysql-server/sql"

	"github.com/dolthub/go-mysql-server/sql/analyzer"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/grafana/pkg/infra/tracing"
)

// DB is a database that can execute SQL queries against a set of Frames.
type DB struct {
	// queryGuard is an optional function that validates SQL queries before execution.
	// It takes a refID and the raw SQL string, returning true if the query is allowed
	// and false with an error if the query should be blocked. If nil, AllowQuery is used as the default.
	queryGuard func(refID, rawSQL string) (bool, error)
}

type QueryOption func(*QueryOptions)

type QueryOptions struct {
	Timeout           time.Duration
	MaxOutputCells    int64
	MaxValueBytes     int64
	MaxProcessedCells int64
}

func WithTimeout(d time.Duration) QueryOption {
	return func(o *QueryOptions) {
		o.Timeout = d
	}
}

func WithMaxOutputCells(n int64) QueryOption {
	return func(o *QueryOptions) {
		o.MaxOutputCells = n
	}
}

// WithMaxValueBytes limits the bytes of string and JSON values the query may
// build, on top of a multiple of the size of its input frames. The limit is
// enforced before each value is built. 0 or less means no limit.
func WithMaxValueBytes(n int64) QueryOption {
	return func(o *QueryOptions) {
		o.MaxValueBytes = n
	}
}

// WithMaxProcessedCells limits the cells the query's plan operators may emit
// in total, on top of a multiple of the number of input cells. 0 or less means
// no limit.
func WithMaxProcessedCells(n int64) QueryOption {
	return func(o *QueryOptions) {
		o.MaxProcessedCells = n
	}
}

// limitAllocationsRuleID identifies limitAllocations among the analyzer rules.
const limitAllocationsRuleID analyzer.RuleId = -1

// QueryFrames runs the sql query query against a database created from frames, and returns the frame.
// The RefID of each frame becomes a table in the database.
// It is expected that there is only one frame per RefID.
// The name becomes the name and RefID of the returned frame.
func (db *DB) QueryFrames(ctx context.Context, tracer tracing.Tracer, name string, query string, frames []*data.Frame, opts ...QueryOption) (*data.Frame, error) {
	guard := db.queryGuard
	if guard == nil {
		// Use the default query guard if none is provided
		// AllowQuery is parsing twice due to TablesList, but don't care for now. We can save the parsed query and reuse it later if we want.
		guard = AllowQuery
	}

	allow, err := guard(name, query)
	if err != nil || !allow {
		return nil, err
	}

	QueryOptions := &QueryOptions{}
	for _, opt := range opts {
		opt(QueryOptions)
	}

	if QueryOptions.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, QueryOptions.Timeout)
		defer cancel()
	}
	_, span := tracer.Start(ctx, "SSE.ExecuteGMSQuery")
	defer span.End()

	pro := NewFramesDBProvider(frames)
	session := mysql.NewBaseSession()

	// Create a new context with the session and tracer
	mCtx := mysql.NewContext(ctx, mysql.WithSession(session), mysql.WithTracer(tracer), mysql.WithDisableFileWrites(true), mysql.WithDisableFileReads(true), mysql.WithTraceRedaction(true))

	// Select the database in the context
	mCtx.SetCurrentDatabase(dbName)

	// Empty dir does not disable secure_file_priv
	//ctx.SetSessionVariable(ctx, "secure_file_priv", "")

	limits := newQueryLimits(QueryOptions.MaxValueBytes, QueryOptions.MaxProcessedCells, frames)

	// TODO: Check if it's wise to reuse the existing provider, rather than creating a new one
	a := analyzer.NewBuilder(pro).
		AddPreAnalyzeRule(limitAllocationsRuleID, limitAllocations(limits)).
		AddPostValidationRule(limitAllocationsRuleID, limitAllocations(limits)).
		Build()
	a.ExecBuilder.PriorityBuilder = &countingBuilder{base: a.ExecBuilder, limits: limits}

	engine := sqle.New(a, &sqle.Config{
		IsReadOnly: true,
	})

	contextErr := func(err error) error {
		if le, ok := asLimitError(err); ok {
			if le.kind == valueBytesLimit {
				return MakeValueBytesLimitExceededError(name, le.limit)
			}
			return MakeProcessedCellLimitExceededError(name, le.limit)
		}
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			return MakeTimeOutError(err, name, QueryOptions.Timeout)
		case errors.Is(err, context.Canceled):
			return MakeCancelError(err, name)
		default:
			return fmt.Errorf("SQL expression for refId %v ended unexpectedly: %w", name, err)
		}
	}

	// Execute the query (planning + iterator construction)
	schema, iter, _, err := engine.Query(mCtx, query)
	if err != nil {
		if _, ok := asLimitError(err); ok {
			return nil, contextErr(err)
		}
		if ctx.Err() != nil {
			return nil, contextErr(ctx.Err())
		}
		return nil, MakeGMSError(name, err)
	}

	// Convert the iterator into a Grafana data.Frame
	f, err := convertToDataFrame(mCtx, iter, schema, QueryOptions.MaxOutputCells, limits)
	if err != nil {
		if _, ok := asLimitError(err); ok {
			return nil, contextErr(err)
		}
		if ctx.Err() != nil {
			return nil, contextErr(ctx.Err())
		}
		return nil, err
	}

	f.Name = name
	f.RefID = name

	return f, nil
}
