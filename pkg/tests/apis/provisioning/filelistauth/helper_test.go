package filelistauth

import (
	"testing"

	"github.com/grafana/grafana/pkg/tests/apis/provisioning/common"
)

// Default feature toggles: provisioningFolderMetadata is on, so folder ACLs on
// provisioned folders can be changed. The main provisioning suite turns that
// toggle off.
var env = common.NewSharedEnv()

func sharedHelper(t *testing.T) *common.ProvisioningTestHelper {
	t.Helper()
	return common.SharedHelper(t, env)
}

func TestMain(m *testing.M) {
	env.RunTestMain(m)
}
