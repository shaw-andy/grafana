package plugins

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/mock"
	"github.com/grafana/grafana/pkg/services/apiserver"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/setting"
)

func TestPluginStoreServiceLoadingRegistersMetaReaderForViewer(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "plugins"), 0o755))
	registerer := prometheus.NewRegistry()

	t.Run("enabled", func(t *testing.T) {
		ac := &mock.Mock{}
		_, err := ProvideAppInstaller(
			staticRootConfig{path: root},
			apiserver.WithoutRestConfig,
			nil,
			nil,
			ac,
			nil,
			featuremgmt.WithFeatures(featuremgmt.FlagPluginStoreServiceLoading),
			registerer,
		)
		require.NoError(t, err)
		require.NotEmpty(t, ac.Calls.DeclareFixedRoles)
		registrations := ac.Calls.DeclareFixedRoles[0].([]any)[0].([]accesscontrol.RoleRegistration)
		require.True(t, viewerCanReadAllMetas(registrations))
	})

	t.Run("disabled", func(t *testing.T) {
		ac := &mock.Mock{}
		_, err := ProvideAppInstaller(
			staticRootConfig{path: root},
			apiserver.WithoutRestConfig,
			nil,
			nil,
			ac,
			nil,
			featuremgmt.WithFeatures(),
			registerer,
		)
		require.NoError(t, err)
		require.Empty(t, ac.Calls.DeclareFixedRoles)
	})
}

func viewerCanReadAllMetas(registrations []accesscontrol.RoleRegistration) bool {
	for _, registration := range registrations {
		recipients := accesscontrol.BuiltInRolesWithParents(registration.Grants)
		if _, ok := recipients[string(org.RoleViewer)]; !ok {
			continue
		}
		for _, perm := range registration.Role.Permissions {
			if perm.Action == ActionPluginsPluginsMetaRead && perm.Scope == ScopeAllPluginsPluginsMeta {
				return true
			}
		}
	}
	return false
}

type staticRootConfig struct {
	path string
}

func (s staticRootConfig) Get(context.Context) (*setting.Cfg, error) {
	return &setting.Cfg{StaticRootPath: s.path}, nil
}

func (s staticRootConfig) GetSections(context.Context, ...string) (*ini.File, error) {
	return ini.Empty(), nil
}
