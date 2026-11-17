package mathexp

import (
	"fmt"

	"github.com/grafana/grafana-plugin-sdk-go/data"
)

// bytesPerCell is the estimated heap cost of one element of a frame field.
// A Series row has two cells, so a row costs bytesPerDatapoint.
const bytesPerCell = bytesPerDatapoint / 2

// EstimateSeriesBytes returns the estimated heap cost of a Series with the
// given number of points, using the same per-point cost as math expressions.
func EstimateSeriesBytes(points int) int64 {
	return int64(points)*bytesPerDatapoint + frameOverhead
}

// MemoryBudget bounds the estimated bytes of expression output that one
// pipeline execution retains. A nil *MemoryBudget has no limit. It is not safe
// for concurrent use.
type MemoryBudget struct {
	limit   int64
	used    int64
	charged map[*data.Field]struct{}
}

// NewMemoryBudget returns a budget of limit bytes, or nil (no limit) when
// limit is not positive.
func NewMemoryBudget(limit int64) *MemoryBudget {
	if limit <= 0 {
		return nil
	}
	return &MemoryBudget{limit: limit, charged: map[*data.Field]struct{}{}}
}

// Check returns an error when allocating bytes more would exceed the budget.
// It does not charge anything.
func (b *MemoryBudget) Check(refID string, bytes int64) error {
	if b == nil || bytes <= b.limit-b.used {
		return nil
	}
	return b.exceededErr(refID, bytes)
}

// Charge adds the estimated size of vals to the budget, or returns an error
// and charges nothing when that would exceed it. Fields already charged are
// not counted again, because pass-through expressions such as `$A` return
// their input's frames.
func (b *MemoryBudget) Charge(refID string, vals Values) error {
	if b == nil {
		return nil
	}
	var bytes int64
	fields := map[*data.Field]struct{}{}
	for _, v := range vals {
		if v == nil {
			continue
		}
		frame := v.AsDataFrame()
		if frame == nil {
			continue
		}
		newFrame := false
		for _, f := range frame.Fields {
			if f == nil {
				continue
			}
			if _, ok := b.charged[f]; ok {
				continue
			}
			if _, ok := fields[f]; ok {
				continue
			}
			newFrame = true
			fields[f] = struct{}{}
			bytes += int64(f.Len()) * bytesPerCell
		}
		if newFrame {
			bytes += frameOverhead
		}
	}
	if err := b.Check(refID, bytes); err != nil {
		return err
	}
	b.used += bytes
	for f := range fields {
		b.charged[f] = struct{}{}
	}
	return nil
}

func (b *MemoryBudget) exceededErr(refID string, bytes int64) error {
	return fmt.Errorf(
		"expression %s needs an estimated %s, which exceeds the expression memory limit for this request (%s of %s already used)",
		refID, formatBytes(bytes), formatBytes(b.used), formatBytes(b.limit),
	)
}
