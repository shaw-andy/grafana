package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/grafana/grafana-app-sdk/app"
	"github.com/grafana/grafana-app-sdk/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/apps/dashvalidator/pkg/cache"
	"github.com/grafana/grafana/apps/dashvalidator/pkg/validator"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/datasources"
)

// checkMaxBodyBytes is the most the compatibility check may buffer from a POST.
// A few megabytes holds a dashboard document. One byte past this must be refused
// with 413 before the rest of the body is read, so a caller cannot force the
// process to allocate the entire payload.
const checkMaxBodyBytes int64 = 4 << 20

func TestCheckRoute_OversizedBodyIsRejectedWithoutBuffering(t *testing.T) {
	const extra = 1 << 20 // well past the single overflow-detection byte
	bodySize := checkMaxBodyBytes + extra

	t.Run("editor allowed for the datasource", func(t *testing.T) {
		assertOversizedBodyRejected(t, bodySize, editorRequester(datasources.ScopeProvider.GetResourceScopeUID("prom-1")))
	})

	t.Run("editor allowed for a different datasource", func(t *testing.T) {
		// Route-level auth only requires some datasource. The body must still be
		// refused before the handler parses it and applies the per-datasource check.
		assertOversizedBodyRejected(t, bodySize, editorRequester(datasources.ScopeProvider.GetResourceScopeUID("other-ds")))
	})
}

func TestCheckRoute_BodyAtLimitReachesDatasourceAuthorization(t *testing.T) {
	// A body at the cap is still a real check. It must be parsed and authorized
	// against the datasource UID inside it, which this caller cannot query.
	body := newCheckBody(t, checkMaxBodyBytes)
	recorder := postCheck(t, body, editorRequester(datasources.ScopeProvider.GetResourceScopeUID("other-ds")))

	require.LessOrEqual(t, body.read, checkMaxBodyBytes+1)
	require.Equal(t, http.StatusForbidden, recorder.Code, "a body at the cap must reach the per-datasource check, got %d", recorder.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &resp))
	assert.Equal(t, "datasource_forbidden", resp["code"])
	assert.Contains(t, resp["error"], "prom-1")
}

func assertOversizedBodyRejected(t *testing.T, bodySize int64, user identity.Requester) {
	t.Helper()

	body := newCheckBody(t, bodySize)
	var panicVal any
	var recorder *httptest.ResponseRecorder
	func() {
		defer func() {
			panicVal = recover()
		}()
		recorder = postCheck(t, body, user)
	}()

	require.Nil(t, panicVal, "oversized body was parsed far enough to reach a nil dependency after reading %d bytes: %v", body.read, panicVal)
	require.NotNil(t, recorder)
	require.LessOrEqual(t, body.read, checkMaxBodyBytes+1, "handler read %d bytes; limit is %d", body.read, checkMaxBodyBytes)
	require.Equal(t, http.StatusRequestEntityTooLarge, recorder.Code, "status %d after reading %d bytes", recorder.Code, body.read)
}

func postCheck(t *testing.T, body *checkBody, user identity.Requester) *httptest.ResponseRecorder {
	t.Helper()

	application, err := New(app.Config{
		SpecificConfig: &DashValidatorConfig{
			MetricsCache: cache.NewMetricsCache(),
			Validators:   map[string]validator.DatasourceValidator{},
			AC:           acimpl.ProvideAccessControl(nil),
		},
	})
	require.NoError(t, err)

	requestURL, err := url.Parse("http://localhost/apis/dashvalidator.grafana.app/v1alpha1/namespaces/org-1/check")
	require.NoError(t, err)

	req := &app.CustomRouteRequest{
		ResourceIdentifier: resource.FullIdentifier{
			Namespace: "org-1",
			Version:   "v1alpha1",
		},
		Path:    "check",
		URL:     requestURL,
		Method:  http.MethodPost,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		Body:    io.NopCloser(body),
	}

	recorder := httptest.NewRecorder()
	ctx := identity.WithRequester(context.Background(), user)
	err = application.CallCustomRoute(ctx, recorder, req)
	// A size refusal may surface as a returned error after the status is written.
	// Any other failure must still produce the status the handler wrote.
	if recorder.Code == 0 {
		require.NoError(t, err)
	}
	return recorder
}

func editorRequester(datasourceScopes ...string) identity.Requester {
	return &identity.StaticRequester{
		OrgRole: identity.RoleEditor,
		UserID:  1,
		OrgID:   1,
		Permissions: map[int64]map[string][]string{
			1: {
				datasources.ActionRead:            datasourceScopes,
				datasources.ActionQuery:           datasourceScopes,
				dashboards.ActionDashboardsCreate: {"folders:*"},
			},
		},
	}
}

type checkBody struct {
	size   int64
	read   int64
	prefix []byte
	suffix []byte
}

func newCheckBody(t *testing.T, size int64) *checkBody {
	t.Helper()
	prefix := []byte(`{"dashboardJson":{"pad":"`)
	suffix := []byte(`"},"datasourceMappings":[{"uid":"prom-1","type":"prometheus"}]}`)
	require.Greater(t, size, int64(len(prefix)+len(suffix)))
	return &checkBody{size: size, prefix: prefix, suffix: suffix}
}

func (b *checkBody) Read(p []byte) (int, error) {
	if b.read >= b.size {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && b.read < b.size {
		var c byte = 'a'
		switch {
		case b.read < int64(len(b.prefix)):
			c = b.prefix[b.read]
		case b.read >= b.size-int64(len(b.suffix)):
			c = b.suffix[b.read-(b.size-int64(len(b.suffix)))]
		}
		p[n] = c
		n++
		b.read++
	}
	return n, nil
}
