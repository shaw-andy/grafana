package testdatasource

import (
	"context"
	"time"
)

// maxQueryDelay bounds how long a request may block on delays supplied by the
// caller (slow query, flaky query, stream speed). Without it a single request
// can pin a query goroutine indefinitely.
const maxQueryDelay = 5 * time.Second

type delayDeadlineKey struct{}

// withDelayDeadline sets one deadline shared by every delay in the request, so
// adding queries, query types or parallel chunked queries cannot extend it.
func withDelayDeadline(ctx context.Context) context.Context {
	if _, ok := ctx.Value(delayDeadlineKey{}).(time.Time); ok {
		return ctx
	}
	return context.WithValue(ctx, delayDeadlineKey{}, time.Now().Add(maxQueryDelay))
}

// waitFor blocks for d, capped at maxQueryDelay and at the request's delay
// deadline, and returns ctx.Err() as soon as ctx is done.
func waitFor(ctx context.Context, d time.Duration) error {
	d = min(d, maxQueryDelay)
	if deadline, ok := ctx.Value(delayDeadlineKey{}).(time.Time); ok {
		d = min(d, time.Until(deadline))
	}
	if d <= 0 {
		return ctx.Err()
	}

	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
