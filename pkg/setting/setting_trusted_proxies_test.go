package setting

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrustedProxiesSettings(t *testing.T) {
	t.Run("defaults to no trusted proxies and X-Forwarded-For", func(t *testing.T) {
		cfg, err := NewCfgFromBytes([]byte(``))
		require.NoError(t, err)
		require.Empty(t, cfg.TrustedProxies)
		require.Equal(t, "X-Forwarded-For", cfg.TrustedProxyClientIPHeader)
	})

	t.Run("parses addresses and CIDR ranges", func(t *testing.T) {
		cfg, err := NewCfgFromBytes([]byte(`
[security]
trusted_proxies = 10.0.0.0/8, 192.168.1.10 ::1
trusted_proxy_client_ip_header = X-Real-IP
`))
		require.NoError(t, err)
		require.Equal(t, "X-Real-IP", cfg.TrustedProxyClientIPHeader)
		require.Len(t, cfg.TrustedProxies, 3)

		require.True(t, cfg.TrustedProxies[0].Contains(net.ParseIP("10.20.30.40")))
		require.True(t, cfg.TrustedProxies[1].Contains(net.ParseIP("192.168.1.10")))
		require.False(t, cfg.TrustedProxies[1].Contains(net.ParseIP("192.168.1.11")))
		require.True(t, cfg.TrustedProxies[2].Contains(net.ParseIP("::1")))
		require.False(t, cfg.TrustedProxies[2].Contains(net.ParseIP("::2")))
	})

	t.Run("rejects invalid entries", func(t *testing.T) {
		for _, value := range []string{"not-an-ip", "10.0.0.0/33", "10.0.0.1, proxy.local"} {
			_, err := NewCfgFromBytes([]byte("[security]\ntrusted_proxies = " + value + "\n"))
			require.Error(t, err, value)
		}
	})
}
