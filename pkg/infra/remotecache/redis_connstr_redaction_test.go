package remotecache

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/setting"
)

func TestDocumentedRedisConnStrPasswordIsClientCredentialAndMustBeRedacted(t *testing.T) {
	const secret = "connstr-secret-placeholder"
	conn := "network=tcp,addr=127.0.0.1:6379,pool_size=100,db=0,username=grafana,password=" + secret + ",ssl=false"

	opts, err := parseRedisConnStr(conn)
	require.NoError(t, err)
	require.Equal(t, secret, opts.Password)
	require.Equal(t, "grafana", opts.Username)
	require.Equal(t, "127.0.0.1:6379", opts.Addr)

	got := setting.RedactedValue(setting.EnvKey("remote_cache", "connstr"), conn)
	require.NotContains(t, got, secret)
	if got != setting.RedactedPassword {
		require.Contains(t, got, "addr=127.0.0.1:6379")
		require.Contains(t, got, "username=grafana")
	}
}
