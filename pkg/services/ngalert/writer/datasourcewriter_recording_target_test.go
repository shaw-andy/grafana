package writer

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/httpclient"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/datasources"
	dsfakes "github.com/grafana/grafana/pkg/services/datasources/fakes"
	"github.com/grafana/grafana/pkg/services/ngalert/metrics"
)

// Placeholders stand in for the basic-auth username and password a datasource
// stores. The tests compare them to the remote-write request and never use a
// real credential.
const (
	placeholderDeniedBasicAuthUser      = "placeholder-denied-basic-auth-user"
	placeholderDeniedBasicAuthPassword  = "placeholder-denied-basic-auth-password"
	placeholderAllowedBasicAuthUser     = "placeholder-allowed-basic-auth-user"
	placeholderAllowedBasicAuthPassword = "placeholder-allowed-basic-auth-password"
	placeholderSwappedBasicAuthUser     = "placeholder-swapped-basic-auth-user"
	placeholderSwappedBasicAuthPassword = "placeholder-swapped-basic-auth-password"
)

// credentialedDataSources returns the decrypted basic-auth password that belongs
// to the datasource object the caller was given, keyed by that object's user.
type credentialedDataSources struct {
	dsfakes.FakeDataSourceService
	passwords map[string]string
}

func (s *credentialedDataSources) DecryptedValues(_ context.Context, ds *datasources.DataSource) (map[string]string, error) {
	if ds == nil || !ds.BasicAuth {
		return map[string]string{}, nil
	}
	password, ok := s.passwords[ds.BasicAuthUser]
	if !ok {
		return map[string]string{}, nil
	}
	return map[string]string{"basicAuthPassword": password}, nil
}

// relookupDataSources returns the disallowed datasource on the first lookup of
// its UID and a different, allowed datasource on every later lookup. A check
// that accepts the first result and then writes whatever the next lookup
// returns still remote-writes.
type relookupDataSources struct {
	credentialedDataSources
	deniedUID string
	denied    *datasources.DataSource
	swapped   *datasources.DataSource
	lookups   int
}

func (s *relookupDataSources) GetDataSource(ctx context.Context, query *datasources.GetDataSourceQuery) (*datasources.DataSource, error) {
	if query != nil && query.UID == s.deniedUID {
		s.lookups++
		if s.lookups == 1 {
			return s.denied, nil
		}
		return s.swapped, nil
	}
	return s.credentialedDataSources.GetDataSource(ctx, query)
}

func prometheusJSON(allow *bool) *simplejson.Json {
	jd := simplejson.New()
	jd.Set("prometheusType", "Prometheus")
	if allow != nil {
		jd.Set("allowAsRecordingRulesTarget", *allow)
	}
	return jd
}

func boolPtr(v bool) *bool {
	return &v
}

func newRecordingWriter(ds datasources.DataSourceService, defaultUID string) *DatasourceWriter {
	return NewDatasourceWriter(DatasourceWriterConfig{
		Timeout:              time.Second * 5,
		DefaultDatasourceUID: defaultUID,
	}, ds, httpclient.NewProvider(), &mockPluginContextProvider{}, clock.New(), log.New("test"), metrics.NewRemoteWriterMetrics(prometheus.NewRegistry()))
}

func addBasicAuthTarget(t *testing.T, svc *credentialedDataSources, uid, dsType, basicUser string, jsonData *simplejson.Json, target *TestRemoteWriteTarget) *datasources.DataSource {
	t.Helper()
	ds, err := svc.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
		Name:     uid,
		UID:      uid,
		OrgID:    1,
		Type:     dsType,
		JsonData: jsonData,
	})
	require.NoError(t, err)
	ds.OrgID = 1
	ds.URL = target.srv.URL
	ds.BasicAuth = true
	ds.BasicAuthUser = basicUser
	return ds
}

func assertNoRemoteWrite(t *testing.T, targets ...*TestRemoteWriteTarget) {
	t.Helper()
	for _, target := range targets {
		target.mtx.Lock()
		count := target.RequestsCount
		target.mtx.Unlock()
		require.Zero(t, count, "remote write reached %s", target.srv.URL)
	}
}

func assertBasicAuth(t *testing.T, target *TestRemoteWriteTarget, user, password string) {
	t.Helper()
	target.mtx.Lock()
	header := target.LastHeaders.Clone()
	count := target.RequestsCount
	target.mtx.Unlock()
	require.Equal(t, 1, count)
	req := &http.Request{Header: header}
	gotUser, gotPassword, ok := req.BasicAuth()
	require.True(t, ok, "remote write did not use the datasource basic auth")
	require.Equal(t, user, gotUser)
	require.Equal(t, password, gotPassword)
}

func TestDatasourceWriter_RecordingTargetFlag(t *testing.T) {
	series := []map[string]string{{"foo": "1"}}
	frames := frameGenFromLabels(t, data.FrameTypeNumericWide, series)

	deniedSrv := NewTestRemoteWriteTarget(t)
	allowedSrv := NewTestRemoteWriteTarget(t)
	unsetSrv := NewTestRemoteWriteTarget(t)
	amazonSrv := NewTestRemoteWriteTarget(t)
	t.Cleanup(deniedSrv.Close)
	t.Cleanup(allowedSrv.Close)
	t.Cleanup(unsetSrv.Close)
	t.Cleanup(amazonSrv.Close)
	deniedSrv.ExpectedPath = "/api/v1/write"
	allowedSrv.ExpectedPath = "/api/v1/write"
	unsetSrv.ExpectedPath = "/api/v1/write"
	amazonSrv.ExpectedPath = "/api/v1/remote_write"

	svc := &credentialedDataSources{passwords: map[string]string{
		placeholderDeniedBasicAuthUser:  placeholderDeniedBasicAuthPassword,
		placeholderAllowedBasicAuthUser: placeholderAllowedBasicAuthPassword,
	}}
	addBasicAuthTarget(t, svc, "prom-denied", datasources.DS_PROMETHEUS, placeholderDeniedBasicAuthUser, prometheusJSON(boolPtr(false)), deniedSrv)
	addBasicAuthTarget(t, svc, "prom-allowed", datasources.DS_PROMETHEUS, placeholderAllowedBasicAuthUser, prometheusJSON(boolPtr(true)), allowedSrv)
	addBasicAuthTarget(t, svc, "prom-unset", datasources.DS_PROMETHEUS, placeholderAllowedBasicAuthUser, prometheusJSON(nil), unsetSrv)
	amazonJSON := simplejson.New()
	amazonJSON.Set("allowAsRecordingRulesTarget", false)
	addBasicAuthTarget(t, svc, "amp-denied", datasources.DS_AMAZON_PROMETHEUS, placeholderDeniedBasicAuthUser, amazonJSON, amazonSrv)

	writer := newRecordingWriter(svc, "prom-denied")
	resetTargets := func() {
		deniedSrv.Reset()
		allowedSrv.Reset()
		unsetSrv.Reset()
		amazonSrv.Reset()
	}

	t.Run("explicit false does not remote-write the excluded prometheus datasource", func(t *testing.T) {
		resetTargets()
		err := writer.WriteDatasource(context.Background(), "prom-denied", "editor_chosen_metric", time.Now(), frames, 1, map[string]string{"injected": "series"})
		assertNoRemoteWrite(t, deniedSrv, allowedSrv)
		require.Error(t, err)
	})

	t.Run("explicit false does not remote-write an excluded amazon managed prometheus datasource", func(t *testing.T) {
		resetTargets()
		err := writer.WriteDatasource(context.Background(), "amp-denied", "editor_chosen_metric", time.Now(), frames, 1, nil)
		assertNoRemoteWrite(t, amazonSrv, deniedSrv)
		require.Error(t, err)
	})

	t.Run("empty target uid does not fall back to an excluded default datasource", func(t *testing.T) {
		resetTargets()
		err := writer.WriteDatasource(context.Background(), "", "editor_chosen_metric", time.Now(), frames, 1, nil)
		assertNoRemoteWrite(t, deniedSrv, allowedSrv)
		require.Error(t, err)
	})

	t.Run("explicit true remote-writes only that datasource and uses its stored basic auth", func(t *testing.T) {
		resetTargets()
		err := writer.WriteDatasource(context.Background(), "prom-allowed", "kept_metric", time.Now(), frames, 1, nil)
		require.NoError(t, err)
		assertBasicAuth(t, allowedSrv, placeholderAllowedBasicAuthUser, placeholderAllowedBasicAuthPassword)
		assertNoRemoteWrite(t, deniedSrv)
	})

	t.Run("unset flag stays writable while the instance default allows it", func(t *testing.T) {
		resetTargets()
		fresh := newRecordingWriter(svc, "")
		err := fresh.WriteDatasource(context.Background(), "prom-unset", "kept_metric", time.Now(), frames, 1, nil)
		require.NoError(t, err)
		assertBasicAuth(t, unsetSrv, placeholderAllowedBasicAuthUser, placeholderAllowedBasicAuthPassword)
	})

	t.Run("a datasource excluded after a rule was saved is not written by a new writer", func(t *testing.T) {
		target := NewTestRemoteWriteTarget(t)
		t.Cleanup(target.Close)
		target.ExpectedPath = "/api/v1/write"
		freshSvc := &credentialedDataSources{passwords: map[string]string{
			placeholderAllowedBasicAuthUser: placeholderAllowedBasicAuthPassword,
		}}
		ds := addBasicAuthTarget(t, freshSvc, "prom-later", datasources.DS_PROMETHEUS, placeholderAllowedBasicAuthUser, prometheusJSON(boolPtr(true)), target)
		first := newRecordingWriter(freshSvc, "")
		require.NoError(t, first.WriteDatasource(context.Background(), "prom-later", "kept_metric", time.Now(), frames, 1, nil))
		assertBasicAuth(t, target, placeholderAllowedBasicAuthUser, placeholderAllowedBasicAuthPassword)

		ds.JsonData.Set("allowAsRecordingRulesTarget", false)
		target.Reset()
		second := newRecordingWriter(freshSvc, "")
		err := second.WriteDatasource(context.Background(), "prom-later", "kept_metric", time.Now(), frames, 1, nil)
		assertNoRemoteWrite(t, target)
		require.Error(t, err)
	})
}

func TestDatasourceWriter_RecordingTargetRelookupDoesNotWrite(t *testing.T) {
	series := []map[string]string{{"foo": "1"}}
	frames := frameGenFromLabels(t, data.FrameTypeNumericWide, series)

	deniedSrv := NewTestRemoteWriteTarget(t)
	swappedSrv := NewTestRemoteWriteTarget(t)
	t.Cleanup(deniedSrv.Close)
	t.Cleanup(swappedSrv.Close)
	deniedSrv.ExpectedPath = "/api/v1/write"
	swappedSrv.ExpectedPath = "/api/v1/write"

	denied := &datasources.DataSource{
		OrgID:         1,
		UID:           "prom-denied",
		Type:          datasources.DS_PROMETHEUS,
		URL:           deniedSrv.srv.URL,
		JsonData:      prometheusJSON(boolPtr(false)),
		BasicAuth:     true,
		BasicAuthUser: placeholderDeniedBasicAuthUser,
	}
	swapped := &datasources.DataSource{
		OrgID:         1,
		UID:           "prom-denied",
		Type:          datasources.DS_PROMETHEUS,
		URL:           swappedSrv.srv.URL,
		JsonData:      prometheusJSON(boolPtr(true)),
		BasicAuth:     true,
		BasicAuthUser: placeholderSwappedBasicAuthUser,
	}
	svc := &relookupDataSources{
		credentialedDataSources: credentialedDataSources{passwords: map[string]string{
			placeholderDeniedBasicAuthUser:  placeholderDeniedBasicAuthPassword,
			placeholderSwappedBasicAuthUser: placeholderSwappedBasicAuthPassword,
		}},
		deniedUID: denied.UID,
		denied:    denied,
		swapped:   swapped,
	}
	// The embedded fake still has the denied datasource so a lookup that does
	// not go through the UID branch cannot silently select some other target.
	_, err := svc.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
		Name: denied.Name, UID: denied.UID, OrgID: denied.OrgID, Type: denied.Type, JsonData: denied.JsonData,
	})
	require.NoError(t, err)

	writer := newRecordingWriter(svc, "")
	err = writer.WriteDatasource(context.Background(), denied.UID, "editor_chosen_metric", time.Now(), frames, denied.OrgID, nil)
	assertNoRemoteWrite(t, deniedSrv, swappedSrv)
	require.Error(t, err)
	require.GreaterOrEqual(t, svc.lookups, 1)
}
