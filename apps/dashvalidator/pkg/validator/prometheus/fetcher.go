package prometheus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"strings"

	"github.com/grafana/grafana-app-sdk/logging"

	"github.com/grafana/grafana/apps/dashvalidator/pkg/validator"
)

// maxMetricNamesBodyBytes caps how much of a label-values response is buffered.
// It is enforced here rather than relying on the data-proxy response limit,
// which is disabled by default (0) and may be configured higher than this.
const maxMetricNamesBodyBytes int64 = 32 << 20

// maxMetricNames caps how many names are decoded from one response. The byte
// cap alone is not enough: a body of very short names expands to many times its
// size once held as a slice and lookup map in the metrics cache.
const maxMetricNames = 1_000_000

var errTooManyMetricNames = fmt.Errorf("metric names response has more than %d names", maxMetricNames)

// Fetcher fetches available metrics from a Prometheus datasource
type Fetcher struct{}

// NewFetcher creates a new Prometheus metrics fetcher
func NewFetcher() *Fetcher {
	return &Fetcher{}
}

// prometheusResponse represents the Prometheus API response structure
type prometheusResponse struct {
	Status string      `json:"status"`
	Data   metricNames `json:"data"`
	Error  string      `json:"error,omitempty"`
}

type metricNames []string

// UnmarshalJSON decodes names one at a time so a list over maxMetricNames is
// rejected before it is fully materialized.
func (m *metricNames) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		*m = nil
		return nil
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return &json.UnmarshalTypeError{Value: fmt.Sprintf("%v", tok), Type: reflect.TypeOf([]string{})}
	}

	names := metricNames{}
	for dec.More() {
		if len(names) >= maxMetricNames {
			return errTooManyMetricNames
		}
		var name string
		if err := dec.Decode(&name); err != nil {
			return err
		}
		names = append(names, name)
	}
	*m = names
	return nil
}

// FetchMetrics queries Prometheus to get all available metric names
// It uses the /api/v1/label/__name__/values endpoint
// The provided HTTP client should have proper authentication configured
func (f *Fetcher) FetchMetrics(ctx context.Context, datasourceUID, datasourceURL string, client *http.Client) ([]string, error) {
	// Build the API URL
	baseURL, err := url.Parse(datasourceURL)
	if err != nil {
		logging.FromContext(ctx).Debug("invalid datasource URL", "datasourceUID", datasourceUID, "url", datasourceURL, "error", err)
		return nil, validator.NewValidationError(
			validator.ErrCodeDatasourceConfig,
			"invalid datasource URL",
			http.StatusBadRequest,
		).WithCause(err).WithDetail("datasourceUID", datasourceUID)
	}

	// Append Prometheus API endpoint to base URL path using path.Join
	// This correctly handles datasources with existing paths (e.g., /api/prom)
	endpoint := "api/v1/label/__name__/values"
	baseURL.Path = path.Join(baseURL.Path, endpoint)

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL.String(), nil)
	if err != nil {
		return nil, validator.NewValidationError(
			validator.ErrCodeInternal,
			"failed to create HTTP request",
			http.StatusInternalServerError,
		).WithCause(err)
	}

	// Execute the request using the provided authenticated client
	resp, err := client.Do(req)
	if err != nil {
		logging.FromContext(ctx).Debug("upstream request failed", "datasourceUID", datasourceUID, "url", baseURL.String(), "error", err)
		// Check if it's a timeout error
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
			return nil, validator.NewAPITimeoutError(datasourceUID, err)
		}
		// Network or connection error - datasource is unreachable
		return nil, validator.NewDatasourceUnreachableError(datasourceUID, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK && resp.ContentLength > maxMetricNamesBodyBytes {
		return nil, newResponseTooLargeError(datasourceUID)
	}

	// Read one byte past the cap so an oversized body can be told apart from one exactly at the cap.
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxMetricNamesBodyBytes+1))
	if readErr != nil {
		body = []byte("<unable to read response body>")
	}
	bodyTooLarge := int64(len(body)) > maxMetricNamesBodyBytes
	if bodyTooLarge {
		body = body[:maxMetricNamesBodyBytes]
	}

	// Log upstream body once at DEBUG for any non-success status
	if resp.StatusCode != http.StatusOK {
		logging.FromContext(ctx).Debug("upstream response body", "datasourceUID", datasourceUID, "url", baseURL.String(), "statusCode", resp.StatusCode, "body", string(body))
	}

	// Check HTTP status code
	switch resp.StatusCode {
	case http.StatusOK:
		// Success - continue to parse response
	case http.StatusUnauthorized, http.StatusForbidden:
		// Authentication or authorization failure
		return nil, validator.NewDatasourceAuthError(datasourceUID, resp.StatusCode)
	case http.StatusNotFound:
		// Endpoint not found - might not be a valid Prometheus instance
		return nil, validator.NewAPIUnavailableError(
			resp.StatusCode,
			fmt.Errorf("endpoint not found - this may not be a valid Prometheus datasource"),
		).WithDetail("datasourceUID", datasourceUID)
	case http.StatusTooManyRequests:
		// Rate limiting
		return nil, validator.NewValidationError(
			validator.ErrCodeAPIRateLimit,
			"Prometheus API rate limit exceeded",
			http.StatusTooManyRequests,
		).WithDetail("datasourceUID", datasourceUID)
	case http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
		// Upstream service is down or unavailable
		return nil, validator.NewAPIUnavailableError(resp.StatusCode, nil).
			WithDetail("datasourceUID", datasourceUID)
	default:
		// Other error status codes
		return nil, validator.NewAPIUnavailableError(resp.StatusCode, nil).
			WithDetail("datasourceUID", datasourceUID)
	}

	if bodyTooLarge {
		logging.FromContext(ctx).Debug("upstream response exceeds size limit", "datasourceUID", datasourceUID, "url", baseURL.String(), "limitBytes", maxMetricNamesBodyBytes)
		return nil, newResponseTooLargeError(datasourceUID)
	}

	// Parse the response JSON
	var promResp prometheusResponse
	if err := json.Unmarshal(body, &promResp); err != nil {
		if errors.Is(err, errTooManyMetricNames) {
			logging.FromContext(ctx).Debug("upstream response exceeds metric name limit", "datasourceUID", datasourceUID, "url", baseURL.String(), "limitNames", maxMetricNames)
			return nil, validator.NewAPIInvalidResponseError(errTooManyMetricNames.Error(), nil).
				WithDetail("datasourceUID", datasourceUID).WithDetail("limitNames", maxMetricNames)
		}
		logging.FromContext(ctx).Debug("upstream response body", "datasourceUID", datasourceUID, "url", baseURL.String(), "statusCode", resp.StatusCode, "body", string(body))
		return nil, validator.NewAPIInvalidResponseError(
			"response is not valid JSON",
			err,
		).WithDetail("datasourceUID", datasourceUID)
	}

	// Check Prometheus API status field
	if promResp.Status != "success" {
		errorMsg := promResp.Error
		if errorMsg == "" {
			errorMsg = "unknown error"
		}
		logging.FromContext(ctx).Debug("upstream returned error status", "datasourceUID", datasourceUID, "url", baseURL.String(), "prometheusError", errorMsg)
		return nil, validator.NewAPIInvalidResponseError(
			fmt.Sprintf("Prometheus API returned error status: %s", errorMsg),
			nil,
		).WithDetail("datasourceUID", datasourceUID).WithDetail("prometheusError", errorMsg)
	}

	// Validate that we got data
	if promResp.Data == nil {
		logging.FromContext(ctx).Debug("upstream response body", "datasourceUID", datasourceUID, "url", baseURL.String(), "statusCode", resp.StatusCode, "body", string(body))
		return nil, validator.NewAPIInvalidResponseError(
			"response missing 'data' field",
			nil,
		).WithDetail("datasourceUID", datasourceUID)
	}

	return promResp.Data, nil
}

func newResponseTooLargeError(datasourceUID string) *validator.ValidationError {
	return validator.NewAPIInvalidResponseError(
		fmt.Sprintf("metric names response exceeds %d bytes", maxMetricNamesBodyBytes),
		nil,
	).WithDetail("datasourceUID", datasourceUID).WithDetail("limitBytes", maxMetricNamesBodyBytes)
}
