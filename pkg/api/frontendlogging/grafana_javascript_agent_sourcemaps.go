package frontendlogging

import "context"

// TransformException will attempt to resolve all modified source locations in the stacktrace with original source locations.
// Callers handling a request with several exceptions should share one SourceMapResolver across them instead.
func TransformException(ctx context.Context, ex *Exception, store *SourceMapStore) *Exception {
	return store.NewResolver().TransformException(ctx, ex)
}

// TransformException will attempt to resolve modified source locations in the stacktrace with original source locations,
// within the limits of this resolver.
func (r *SourceMapResolver) TransformException(ctx context.Context, ex *Exception) *Exception {
	if ex.Stacktrace == nil {
		return ex
	}
	frames := []Frame{}

	for _, frame := range ex.Stacktrace.Frames {
		mappedFrame, err := r.resolveSourceLocation(ctx, frame)
		if err != nil {
			frames = append(frames, frame)
		} else if mappedFrame != nil {
			frames = append(frames, *mappedFrame)
		} else {
			frames = append(frames, frame)
		}
	}

	return &Exception{
		Type:       ex.Type,
		Value:      ex.Value,
		Stacktrace: &Stacktrace{Frames: frames},
		Timestamp:  ex.Timestamp,
	}
}
