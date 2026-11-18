package features

import (
	"context"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/live"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/datasources/guardian"
	"github.com/grafana/grafana/pkg/services/live/model"
	"github.com/grafana/grafana/pkg/services/live/runstream"
	"github.com/grafana/grafana/pkg/services/user"
	testdatasource "github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource"
)

// viewerPluginContext mirrors the two ways a signed-in user reaches a
// TestData stream handler. An empty datasource UID is the plugin-scope path
// and is not passed through the datasource query check. A UID is the
// datasource-scope path: OSS allows the query for every signed-in user.
type viewerPluginContext struct{}

func (viewerPluginContext) GetPluginContext(_ context.Context, user identity.Requester, pluginID, datasourceUID string, _ bool) (backend.PluginContext, error) {
	if datasourceUID != "" {
		guard := guardian.ProvideGuardian().New(user.GetOrgID(), user, datasources.DataSource{
			ID:    1,
			OrgID: user.GetOrgID(),
			UID:   datasourceUID,
			Type:  datasources.DS_TESTDATA,
		})
		canQuery, err := guard.CanQuery(1)
		if err != nil {
			return backend.PluginContext{}, err
		}
		if !canQuery {
			return backend.PluginContext{}, datasources.ErrDataSourceAccessDenied
		}
	}

	pctx := backend.PluginContext{OrgID: user.GetOrgID(), PluginID: pluginID}
	if datasourceUID != "" {
		pctx.DataSourceInstanceSettings = &backend.DataSourceInstanceSettings{
			UID:  datasourceUID,
			Type: pluginID,
		}
	}
	return pctx, nil
}

type nopPublisher struct{}

func (nopPublisher) PublishLocal(string, []byte) error { return nil }

type noSubscribers struct{}

func (noSubscribers) GetNumLocalSubscribers(string) (int, error) { return 0, nil }

func TestLiveViewerNonFiniteTickSubscribeDoesNotCrash(t *testing.T) {
	viewer := &user.SignedInUser{
		UserID:    2,
		OrgID:     1,
		OrgRole:   identity.RoleViewer,
		Namespace: "default",
		Login:     "viewer",
	}
	guard := guardian.ProvideGuardian().New(viewer.OrgID, viewer, datasources.DataSource{
		ID:    1,
		OrgID: viewer.OrgID,
		UID:   "testdata",
		Type:  datasources.DS_TESTDATA,
	})
	canQuery, err := guard.CanQuery(1)
	require.NoError(t, err)
	require.True(t, canQuery, "OSS datasource guardian allows this viewer to query TestData")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := runstream.NewManager(nopPublisher{}, noSubscribers{}, viewerPluginContext{}, runstream.WithCheckConfig(time.Hour, 3))
	go func() {
		_ = mgr.Run(ctx)
	}()

	svc := testdatasource.ProvideService()
	channels := []string{
		"ds/testdata/sim/flight/NaNhz",
		"ds/testdata/sim/sine/NaNhz",
		"ds/testdata/sim/tank/NaNhz",
		"ds/testdata/sim/flight/NaNhz/instance",
		"plugin/grafana-testdata-datasource/sim/flight/NaNhz",
		"plugin/testdata/sim/sine/NaNhz",
	}

	for _, channel := range channels {
		t.Run(channel, func(t *testing.T) {
			parsed, err := live.ParseChannel(channel)
			require.NoError(t, err)

			pluginID := datasources.DS_TESTDATA
			datasourceUID := parsed.Namespace
			if parsed.Scope == live.ScopePlugin {
				pluginID = parsed.Namespace
				datasourceUID = ""
			} else {
				require.Equal(t, live.ScopeDatasource, parsed.Scope)
			}

			runner := NewPluginRunner(pluginID, datasourceUID, mgr, viewerPluginContext{}, svc)
			handler, err := runner.GetHandlerForPath(parsed.Path)
			require.NoError(t, err)

			_, status, err := handler.OnSubscribe(ctx, viewer, model.SubscribeEvent{
				Channel: channel,
				Path:    parsed.Path,
			})
			accepted := err == nil && status == backend.SubscribeStreamStatusOK
			require.False(t, accepted)

			// The stream manager starts RunStream on its own goroutine after
			// subscribe is accepted. Give that goroutine time to panic if a
			// NaN simulation was stored and then ticked.
			time.Sleep(100 * time.Millisecond)
		})
	}
}

func TestLiveManagerRunStreamNonFiniteTickDoesNotKillProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := runstream.NewManager(nopPublisher{}, noSubscribers{}, viewerPluginContext{}, runstream.WithCheckConfig(time.Hour, 3))
	runDone := make(chan error, 1)
	go func() {
		runDone <- mgr.Run(ctx)
	}()

	svc := testdatasource.ProvideService()
	runner := &recordingRunner{inner: svc, errCh: make(chan error, 1)}
	viewer := &user.SignedInUser{UserID: 2, OrgID: 1, OrgRole: identity.RoleViewer, Namespace: "default"}

	_, err := mgr.SubmitStream(context.Background(), viewer, "default/ds/testdata/sim/flight/NaNhz", "sim/flight/NaNhz", nil, backend.PluginContext{
		OrgID:    viewer.OrgID,
		PluginID: datasources.DS_TESTDATA,
		DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{
			UID:  "testdata",
			Type: datasources.DS_TESTDATA,
		},
	}, runner, false)
	require.NoError(t, err)

	select {
	case runErr := <-runner.errCh:
		require.Error(t, runErr)
		require.NotErrorIs(t, runErr, context.DeadlineExceeded)
		require.NotErrorIs(t, runErr, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("RunStream did not return an error for a NaN tick rate")
	case err := <-runDone:
		t.Fatalf("stream manager stopped while running the NaN simulation: %v", err)
	}
}

type recordingRunner struct {
	inner backend.StreamHandler
	errCh chan error
}

func (r *recordingRunner) RunStream(ctx context.Context, req *backend.RunStreamRequest, sender *backend.StreamSender) error {
	err := r.inner.RunStream(ctx, req, sender)
	select {
	case r.errCh <- err:
	default:
	}
	return err
}
