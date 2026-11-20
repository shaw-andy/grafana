package user

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/setting"
)

// placeholderPassword is a repeated marker. The tests care about length and
// character class, not about any particular secret.
func placeholderPassword(length int) string {
	return strings.Repeat("p", length)
}

func loadShippedDefaults(t *testing.T) *setting.Cfg {
	t.Helper()
	cfg := setting.NewCfg()
	err := cfg.Load(setting.CommandLineArgs{
		HomePath: "../../..",
		Config:   "../../../conf/defaults.ini",
	})
	require.NoError(t, err)
	return cfg
}

func TestShippedDefaultsEnableStrongPasswordPolicy(t *testing.T) {
	cfg := loadShippedDefaults(t)

	require.True(t, cfg.BasicAuthEnabled)
	require.False(t, cfg.DisableLogin)
	require.False(t, cfg.DisableLoginForm)
	require.False(t, cfg.DisableBruteForceLoginProtection)
	require.False(t, cfg.DisableUsernameLoginProtection)
	require.Equal(t, int64(5), cfg.BruteForceLoginProtectionMaxAttempts)
	require.GreaterOrEqual(t, MinPasswordLength, 12)

	require.True(t, cfg.BasicAuthStrongPasswordPolicy, "conf/defaults.ini auth.basic password_policy must be enabled")
}

func TestValidatePasswordRejectsShortPasswordsWhenPolicyDisabled(t *testing.T) {
	cfg := setting.NewCfg()
	cfg.BasicAuthStrongPasswordPolicy = false

	for _, length := range []int{1, 4, 11} {
		t.Run(fmt.Sprintf("length %d", length), func(t *testing.T) {
			err := ValidatePassword(placeholderPassword(length), cfg)
			require.Error(t, err)
			require.True(t, passwordPolicyError(err))
		})
	}

	require.NoError(t, ValidatePassword(placeholderPassword(MinPasswordLength), cfg))

	cfg.BasicAuthStrongPasswordPolicy = true
	err := ValidatePassword(placeholderPassword(MinPasswordLength), cfg)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPasswordPolicyInfringe)
}

func passwordPolicyError(err error) bool {
	return errors.Is(err, ErrPasswordTooShort) || errors.Is(err, ErrPasswordPolicyInfringe)
}
