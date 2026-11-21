package provisioning

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/notifier/legacy_storage"
	v1 "github.com/grafana/grafana/pkg/services/ngalert/notifier/legacy_storage/v1"
)

// Names that are not a single URL path segment. Placing one of these into the mute-timing
// export path without encoding lets the browser resolve the request onto another route.
func baseAlertmanagerConfig() *v1.AMConfigV1 {
	receiver := v1.NewReceiver("default", nil, models.ProvenanceNone)
	return &v1.AMConfigV1{
		Receivers: map[v1.ResourceUID]v1.PostableApiReceiver{
			receiver.UID: receiver,
		},
		AlertmanagerConfig: v1.PostableApiAlertingConfig{
			Config: v1.Config{
				Route: &v1.Route{Receiver: receiver.Name},
			},
		},
	}
}

func titlesAfterSave(t *testing.T, revision *legacy_storage.ConfigRevision) []string {
	t.Helper()
	raw, err := legacy_storage.SerializeAlertmanagerConfig(*revision.Config)
	require.NoError(t, err)
	db, err := legacy_storage.DeserializeAlertmanagerConfig(raw)
	require.NoError(t, err)
	restored := v1.ToModel(db)
	titles := make([]string, 0, len(restored.TimeIntervals))
	for _, interval := range restored.TimeIntervals {
		titles = append(titles, interval.Title)
	}
	return titles
}

func unsafeMuteTimingNames() []string {
	return []string{
		// Parent-directory segments and a query delimiter. Five ".." segments climb out of
		// /api/v1/provisioning/mute-timings/ to the origin root, and "?" drops the "/export/" suffix.
		"../../../../../logout?",
		"foo/../logout",
		"week/end",
		"..",
		".",
		"foo?bar",
		"foo#bar",
		`foo\bar`,
	}
}

func TestCreateMuteTimingRejectsNamesThatAreNotOnePathSegment(t *testing.T) {
	orgID := int64(1)

	for _, name := range unsafeMuteTimingNames() {
		t.Run(name, func(t *testing.T) {
			sut, store, prov := createMuteTimingSvcSut()
			prov.EXPECT().SetProvenance(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
			var written []string
			store.GetFn = func(ctx context.Context, orgID int64) (*legacy_storage.ConfigRevision, error) {
				return &legacy_storage.ConfigRevision{Config: baseAlertmanagerConfig()}, nil
			}
			store.SaveFn = func(ctx context.Context, revision *legacy_storage.ConfigRevision) error {
				written = titlesAfterSave(t, revision)
				return nil
			}

			_, err := sut.CreateMuteTiming(context.Background(), v1.TimeInterval{Title: name}, orgID)

			require.Errorf(t, err, "CreateMuteTiming stored name %q", name)
			require.Truef(t, ErrTimeIntervalInvalid.Base.Is(err), "expected ErrTimeIntervalInvalid but got %s", err)
			require.NotContains(t, written, name, "rejected name was written before the request failed")
		})
	}

	t.Run("single path segment is stored and listed", func(t *testing.T) {
		const name = "business-hours"
		sut, store, prov := createMuteTimingSvcSut()
		var saved *legacy_storage.ConfigRevision
		store.GetFn = func(ctx context.Context, orgID int64) (*legacy_storage.ConfigRevision, error) {
			if saved != nil {
				return saved, nil
			}
			return &legacy_storage.ConfigRevision{Config: baseAlertmanagerConfig()}, nil
		}
		store.SaveFn = func(ctx context.Context, revision *legacy_storage.ConfigRevision) error {
			raw, err := legacy_storage.SerializeAlertmanagerConfig(*revision.Config)
			require.NoError(t, err)
			db, err := legacy_storage.DeserializeAlertmanagerConfig(raw)
			require.NoError(t, err)
			saved = &legacy_storage.ConfigRevision{Config: v1.ToModel(db)}
			return nil
		}
		prov.EXPECT().SetProvenance(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
		prov.EXPECT().GetProvenances(mock.Anything, mock.Anything, mock.Anything).Return(map[string]models.Provenance{}, nil)

		created, err := sut.CreateMuteTiming(context.Background(), v1.TimeInterval{
			ResourceMetadata: v1.ResourceMetadata{Provenance: models.ProvenanceAPI},
			Title:            name,
		}, orgID)
		require.NoError(t, err)
		require.Equal(t, name, created.Title)

		listed, err := sut.GetMuteTimings(context.Background(), orgID)
		require.NoError(t, err)
		require.Len(t, listed, 1)
		require.Equal(t, name, listed[0].Title)
	})
}

func TestUpdateMuteTimingRejectsNamesThatAreNotOnePathSegment(t *testing.T) {
	orgID := int64(1)
	const originalName = "weekends"

	for _, name := range unsafeMuteTimingNames() {
		t.Run(name, func(t *testing.T) {
			sut, store, prov := createMuteTimingSvcSut()
			initialCfg := baseAlertmanagerConfig()
			initialCfg.TimeIntervals = map[v1.ResourceUID]v1.TimeInterval{
				v1.TimeIntervalUID(originalName): v1.NewTimeInterval(originalName, nil, models.ProvenanceNone),
			}
			var written []string
			store.GetFn = func(ctx context.Context, orgID int64) (*legacy_storage.ConfigRevision, error) {
				return &legacy_storage.ConfigRevision{Config: initialCfg}, nil
			}
			store.SaveFn = func(ctx context.Context, revision *legacy_storage.ConfigRevision) error {
				written = titlesAfterSave(t, revision)
				return nil
			}
			prov.EXPECT().GetProvenances(mock.Anything, mock.Anything, mock.Anything).Return(map[string]models.Provenance{}, nil).Maybe()
			prov.EXPECT().SetProvenance(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
			prov.EXPECT().DeleteProvenance(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

			_, err := sut.UpdateMuteTiming(context.Background(), v1.TimeInterval{
				ResourceMetadata: v1.ResourceMetadata{UID: v1.TimeIntervalUID(originalName)},
				Title:            name,
			}, orgID)

			require.Errorf(t, err, "UpdateMuteTiming renamed %q to %q", originalName, name)
			require.Truef(t, ErrTimeIntervalInvalid.Base.Is(err), "expected ErrTimeIntervalInvalid but got %s", err)
			require.NotContains(t, written, name, "rejected name was written before the request failed")
		})
	}
}
