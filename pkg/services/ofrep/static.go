package ofrep

import (
	"context"
	"net/http"
	"slices"

	"github.com/grafana/grafana/pkg/infra/tracing"
	goffmodel "github.com/thomaspoignant/go-feature-flag/cmd/relayproxy/model"
	"go.opentelemetry.io/otel/attribute"
)

func (b *APIBuilder) evalAllFlagsStatic(ctx context.Context, isAuthedUser bool, w http.ResponseWriter) {
	ctx, span := tracing.Start(ctx, "ofrep.static.evalAllFlags")
	defer span.End()
	logger := b.logger.FromContext(ctx)

	result, err := b.staticEvaluator.EvalAllFlags(ctx)
	if err != nil {
		err = tracing.Error(span, err)
		logger.Error("Failed to evaluate all static flags", "error", err)
		http.Error(w, "failed to evaluate flags", http.StatusInternalServerError)
		return
	}

	span.SetAttributes(attribute.Int("total_flags_count", len(result.Flags)))

	if !isAuthedUser {
		result.Flags = slices.DeleteFunc(result.Flags, func(f goffmodel.OFREPFlagBulkEvaluateSuccessResponse) bool {
			return !visibleToUnauthenticated(f.OFREPEvaluateSuccessResponse)
		})
		span.SetAttributes(attribute.Int("visible_flags_count", len(result.Flags)))
	}

	writeResponse(http.StatusOK, result, logger, w)
}

func (b *APIBuilder) evalFlagStatic(ctx context.Context, flagKey string, isAuthedUser bool, w http.ResponseWriter) {
	ctx, span := tracing.Start(ctx, "ofrep.static.evalFlag")
	defer span.End()
	logger := b.logger.FromContext(ctx)

	span.SetAttributes(attribute.String("flag_key", flagKey))

	result, err := b.staticEvaluator.EvalFlag(ctx, flagKey)

	// Unknown flags, failed evaluations and hidden flags all look the same to an
	// unauthenticated caller, so the response cannot be used to probe which flags exist.
	if !isAuthedUser && (err != nil || !visibleToUnauthenticated(result)) {
		logger.Debug("Unauthed request for non-public static flag, responding as not-found", "key", flagKey)
		writeResponse(http.StatusNotFound, flagNotFoundResponse(flagKey), logger, w)
		return
	}

	if err != nil {
		err = tracing.Error(span, err)
		logger.Error("Failed to evaluate static flag", "key", flagKey, "error", err)
		http.Error(w, "failed to evaluate flag", http.StatusInternalServerError)
		return
	}

	writeResponse(http.StatusOK, result, logger, w)
}

// visibleToUnauthenticated reports whether a static evaluation may be returned to a
// caller that is not signed in. Besides flags marked public, boolean flags that are on
// are allowed: the boot data served to anonymous visitors already lists every enabled
// flag, and the frontend evaluates flags before sign-in. Flags that are off and
// non-boolean values are never returned.
func visibleToUnauthenticated(result goffmodel.OFREPEvaluateSuccessResponse) bool {
	if isPublic(result.Metadata) {
		return true
	}
	on, ok := result.Value.(bool)
	return ok && on
}
