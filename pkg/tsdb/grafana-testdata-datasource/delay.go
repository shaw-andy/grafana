package testdatasource

import (
	"context"
	"time"
)

// maxQueryDelay bounds every simulated delay, and the total of all simulated
// delays within one query request, so a caller cannot hold a server goroutine
// for an arbitrary amount of time.
const maxQueryDelay = 5 * time.Second

type delayDeadlineKey struct{}

// withDelayBudget gives all simulated delays made with ctx a shared deadline,
// so splitting a delay across several queries or scenarios does not extend it.
func withDelayBudget(ctx context.Context) context.Context {
	return context.WithValue(ctx, delayDeadlineKey{}, time.Now().Add(maxQueryDelay))
}

// parseQueryDelay returns the delay described by raw, or zero when raw is not a
// positive duration of at most maxQueryDelay.
func parseQueryDelay(raw string) time.Duration {
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 || d > maxQueryDelay {
		return 0
	}
	return d
}

// sleepContext waits for d, capped by maxQueryDelay and by any budget attached
// with withDelayBudget, and returns early with the context error if ctx is done.
func sleepContext(ctx context.Context, d time.Duration) error {
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
