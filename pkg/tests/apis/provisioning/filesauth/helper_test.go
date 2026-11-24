package filesauth

import (
	"testing"

	"github.com/grafana/grafana/pkg/tests/apis/provisioning/common"
	"github.com/grafana/grafana/pkg/tests/testinfra"
)

// Folder metadata stays at its default (enabled). This package does not start
// a Git server; the files API is exercised against a local repository.
var env = common.NewSharedEnv(
	func(opts *testinfra.GrafanaOpts) {
		opts.SecretsManagerEnableDBMigrations = true
	},
)

func sharedHelper(t *testing.T) *common.ProvisioningTestHelper {
	t.Helper()
	return common.SharedHelper(t, env)
}

func TestMain(m *testing.M) {
	env.RunTestMain(m)
}
