package expr

import (
	"context"

	"github.com/grafana/grafana/pkg/expr/mathexp"
)

type memoryBudgetKey struct{}

func withMemoryBudget(ctx context.Context, b *mathexp.MemoryBudget) context.Context {
	return context.WithValue(ctx, memoryBudgetKey{}, b)
}

// memoryBudgetFromContext returns the budget of the executing pipeline, or nil
// (no limit) when the command runs outside one.
func memoryBudgetFromContext(ctx context.Context) *mathexp.MemoryBudget {
	b, _ := ctx.Value(memoryBudgetKey{}).(*mathexp.MemoryBudget)
	return b
}
