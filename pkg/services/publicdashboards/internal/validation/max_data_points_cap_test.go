package validation

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/publicdashboards/internal/models"
)

// publicDashboardSafeResolution is the bound getSafeIntervalAndMaxDataPoints
// documents for every public dashboard query.
const publicDashboardSafeResolution = int64(11000)

func TestValidateQueryPublicDashboardRequest_RejectsMaxDataPointsAboveSafeResolution(t *testing.T) {
	pd := &models.PublicDashboard{TimeSelectionEnabled: false}

	t.Run("maxDataPoints above 11000 is rejected", func(t *testing.T) {
		err := ValidateQueryPublicDashboardRequest(models.PublicDashboardQueryDTO{
			IntervalMs:    int64(7 * 24 * 60 * 60 * 1000),
			MaxDataPoints: publicDashboardSafeResolution + 1,
		}, pd)
		require.Error(t, err)
	})

	t.Run("maxDataPoints at 11000 is accepted", func(t *testing.T) {
		err := ValidateQueryPublicDashboardRequest(models.PublicDashboardQueryDTO{
			IntervalMs:    int64(7 * 24 * 60 * 60 * 1000),
			MaxDataPoints: publicDashboardSafeResolution,
		}, pd)
		require.NoError(t, err)
	})

	t.Run("a very large maxDataPoints is rejected", func(t *testing.T) {
		err := ValidateQueryPublicDashboardRequest(models.PublicDashboardQueryDTO{
			IntervalMs:    int64(7 * 24 * 60 * 60 * 1000),
			MaxDataPoints: 50_000_000,
		}, pd)
		require.Error(t, err)
	})
}
