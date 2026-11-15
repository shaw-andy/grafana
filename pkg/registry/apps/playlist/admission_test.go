package playlist

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/client-go/rest"

	"github.com/grafana/grafana-app-sdk/app"
	appsdkapiserver "github.com/grafana/grafana-app-sdk/k8s/apiserver"
	"github.com/grafana/grafana-app-sdk/simple"
	"github.com/grafana/grafana/apps/playlist/pkg/apis/manifestdata"
	playlistv0 "github.com/grafana/grafana/apps/playlist/pkg/apis/playlist/v0alpha1"
	playlistv1 "github.com/grafana/grafana/apps/playlist/pkg/apis/playlist/v1"
	playlistapp "github.com/grafana/grafana/apps/playlist/pkg/app"
)

// playlistAdmission builds the same validating admission plugin the API server
// registers for playlist create and update. ErrNotImplemented from the app is
// treated as success by that plugin, so these tests call the plugin itself.
func playlistAdmission(t *testing.T) admission.ValidationInterface {
	t.Helper()

	specific := any(&playlistapp.PlaylistConfig{})
	provider := simple.NewAppProvider(manifestdata.LocalManifest(), specific, playlistapp.New)
	cfg := app.Config{
		KubeConfig:     rest.Config{},
		ManifestData:   *manifestdata.LocalManifest().ManifestData,
		SpecificConfig: specific,
	}
	installer, err := appsdkapiserver.NewDefaultAppInstaller(provider, cfg, manifestdata.NewGoTypeAssociator())
	require.NoError(t, err)
	require.NoError(t, installer.InitializeApp(rest.Config{}))

	factory := installer.AdmissionPlugin()
	require.NotNil(t, factory)
	plugin, err := factory(nil)
	require.NoError(t, err)
	validator, ok := plugin.(admission.ValidationInterface)
	require.True(t, ok)
	return validator
}

func TestPlaylistAdmissionDashboardByID(t *testing.T) {
	validator := playlistAdmission(t)

	rejected := []string{
		"../../../logout",
		"../../../profile/switch-org/2",
		"%2e%2e/%2e%2e/%2e%2e/logout",
		`..\..\..\logout`,
		`..\..\..\profile\switch-org\2`,
		"..%2f..%2f..%2flogout",
		"1/2",
		"1 2",
		"1,2a",
		"",
	}
	accepted := []string{"1", "1,2", "1,2,3", "42"}

	versions := []struct {
		name    string
		version string
		object  func(value string) runtime.Object
	}{
		{
			name:    "v1",
			version: "v1",
			object: func(value string) runtime.Object {
				obj := playlistv1.NewPlaylist()
				obj.APIVersion = "playlist.grafana.app/v1"
				obj.Kind = "Playlist"
				obj.Name = "shared"
				obj.Spec.Title = "shared"
				obj.Spec.Interval = "5m"
				obj.Spec.Items = []playlistv1.PlaylistItem{{
					Type:  playlistv1.PlaylistPlaylistItemTypeDashboardById,
					Value: value,
				}}
				return obj
			},
		},
		{
			name:    "v0alpha1",
			version: "v0alpha1",
			object: func(value string) runtime.Object {
				obj := playlistv0.NewPlaylist()
				obj.APIVersion = "playlist.grafana.app/v0alpha1"
				obj.Kind = "Playlist"
				obj.Name = "shared"
				obj.Spec.Title = "shared"
				obj.Spec.Interval = "5m"
				obj.Spec.Items = []playlistv0.PlaylistItem{{
					Type:  playlistv0.PlaylistPlaylistItemTypeDashboardById,
					Value: value,
				}}
				return obj
			},
		},
	}

	for _, version := range versions {
		t.Run(version.name, func(t *testing.T) {
			for _, op := range []admission.Operation{admission.Create, admission.Update} {
				t.Run(string(op), func(t *testing.T) {
					for _, value := range rejected {
						t.Run("reject "+value, func(t *testing.T) {
							obj := version.object(value)
							// A safe stored object must not make an unsafe replacement succeed.
							var old runtime.Object
							if op == admission.Update {
								old = version.object("1")
							}
							err := validator.Validate(context.Background(), admissionAttributes(version.version, op, obj, old), nil)
							require.Error(t, err)
						})
					}
					for _, value := range accepted {
						t.Run("allow "+value, func(t *testing.T) {
							obj := version.object(value)
							var old runtime.Object
							if op == admission.Update {
								// The previous object is the unsafe one. Admission has to judge the object being written.
								old = version.object("../../../logout")
							}
							err := validator.Validate(context.Background(), admissionAttributes(version.version, op, obj, old), nil)
							require.NoError(t, err)
						})
					}
					t.Run("reject when a later item is unsafe", func(t *testing.T) {
						obj := version.object("1")
						switch typed := obj.(type) {
						case *playlistv1.Playlist:
							typed.Spec.Items = append(typed.Spec.Items, playlistv1.PlaylistItem{
								Type:  playlistv1.PlaylistPlaylistItemTypeDashboardById,
								Value: "../../../logout",
							})
						case *playlistv0.Playlist:
							typed.Spec.Items = append(typed.Spec.Items, playlistv0.PlaylistItem{
								Type:  playlistv0.PlaylistPlaylistItemTypeDashboardById,
								Value: "../../../profile/switch-org/2",
							})
						}
						err := validator.Validate(context.Background(), admissionAttributes(version.version, op, obj, nil), nil)
						require.Error(t, err)
					})
					t.Run("allow uid and tag values", func(t *testing.T) {
						obj := version.object("1")
						switch typed := obj.(type) {
						case *playlistv1.Playlist:
							typed.Spec.Items = []playlistv1.PlaylistItem{
								{Type: playlistv1.PlaylistPlaylistItemTypeDashboardByUid, Value: "dash-uid"},
								{Type: playlistv1.PlaylistPlaylistItemTypeDashboardByTag, Value: "prod"},
							}
						case *playlistv0.Playlist:
							typed.Spec.Items = []playlistv0.PlaylistItem{
								{Type: playlistv0.PlaylistPlaylistItemTypeDashboardByUid, Value: "dash-uid"},
								{Type: playlistv0.PlaylistPlaylistItemTypeDashboardByTag, Value: "prod"},
							}
						}
						err := validator.Validate(context.Background(), admissionAttributes(version.version, op, obj, nil), nil)
						require.NoError(t, err)
					})
				})
			}
		})
	}
}

func admissionAttributes(version string, op admission.Operation, obj, old runtime.Object) admission.Attributes {
	gvk := schema.GroupVersionKind{Group: "playlist.grafana.app", Version: version, Kind: "Playlist"}
	gvr := schema.GroupVersionResource{Group: gvk.Group, Version: version, Resource: "playlists"}
	return admission.NewAttributesRecord(obj, old, gvk, "default", "shared", gvr, "", op, nil, false, &userInfo{})
}

type userInfo struct{}

func (userInfo) GetName() string               { return "editor" }
func (userInfo) GetUID() string                { return "editor" }
func (userInfo) GetGroups() []string           { return nil }
func (userInfo) GetExtra() map[string][]string { return nil }
