package metrics

import (
	"fmt"
	"math"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// MaxFrontendMetricEvents caps how many events one report may contain. The
	// frontend flushes a handful of boot and load timings per interval.
	MaxFrontendMetricEvents = 32
	// MaxFrontendMetricsBodyBytes caps the request body of a frontend metrics report.
	MaxFrontendMetricsBodyBytes = 64 << 10

	// The histograms are process-wide, so a single observation must not be able
	// to dominate their sums. No real boot or preload timing exceeds an hour.
	maxFrontendMetricSeconds = 3600
)

// PostPostFrontendMetricsCommand sent by frontend to record frontend metrics
type PostFrontendMetricsCommand struct {
	Events []FrontendMetricEvent `json:"events"`
}

// Validate rejects the whole report if any event is out of bounds, so that a
// report is either recorded completely or not at all.
func (cmd *PostFrontendMetricsCommand) Validate() error {
	if len(cmd.Events) > MaxFrontendMetricEvents {
		return fmt.Errorf("too many frontend metric events: %d, max %d", len(cmd.Events), MaxFrontendMetricEvents)
	}
	for _, event := range cmd.Events {
		if err := event.validate(); err != nil {
			return err
		}
	}
	return nil
}

// FrontendMetricEvent a single metric measurement event
type FrontendMetricEvent struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
}

func (event FrontendMetricEvent) validate() error {
	return validateFrontendMetricValue(event.Name, event.Value, frontendMetricMaxValues[event.Name])
}

func validateFrontendMetricValue(name string, value float64, maxValue float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return fmt.Errorf("invalid value for frontend metric %q", name)
	}
	if maxValue > 0 && value > maxValue {
		return fmt.Errorf("value for frontend metric %q exceeds %g", name, maxValue)
	}
	return nil
}

// FrontendMetricsRecorder handles the recording of the event, ie passes it to a prometheus metric
type FrontendMetricsRecorder func(event FrontendMetricEvent)

// FrontendMetrics contains all the valid frontend metrics and a handler function for recording events
var FrontendMetrics map[string]FrontendMetricsRecorder = map[string]FrontendMetricsRecorder{}

var frontendMetricMaxValues = map[string]float64{}

func registerFrontendHistogram(reg prometheus.Registerer, name string, help string, maxValue float64) {
	defBuckets := []float64{.1, .25, .5, 1, 1.5, 2, 5, 10, 20, 40}

	histogram := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:      name,
		Help:      help,
		Buckets:   defBuckets,
		Namespace: ExporterName,
	})

	frontendMetricMaxValues[name] = maxValue
	FrontendMetrics[name] = func(event FrontendMetricEvent) {
		if validateFrontendMetricValue(name, event.Value, maxValue) != nil {
			return
		}
		histogram.Observe(event.Value)
	}

	reg.MustRegister(histogram)
}

func initFrontendMetrics(r prometheus.Registerer) {
	registerFrontendHistogram(r, "frontend_boot_load_time_seconds", "Frontend boot time measurement", maxFrontendMetricSeconds)
	registerFrontendHistogram(r, "frontend_boot_first_paint_time_seconds", "Frontend boot first paint", maxFrontendMetricSeconds)
	registerFrontendHistogram(r, "frontend_boot_first_contentful_paint_time_seconds", "Frontend boot first contentful paint", maxFrontendMetricSeconds)
	registerFrontendHistogram(r, "frontend_boot_js_done_time_seconds", "Frontend boot initial js load", maxFrontendMetricSeconds)
	registerFrontendHistogram(r, "frontend_boot_css_time_seconds", "Frontend boot initial css load", maxFrontendMetricSeconds)
	registerFrontendHistogram(r, "frontend_plugins_preload_ms", "Frontend preload plugin time measurement", maxFrontendMetricSeconds*1000)
}
