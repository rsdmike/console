package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeepEnvOnlyEASecrets(t *testing.T) {
	t.Parallel()

	env := map[string]string{"EA_PASSWORD": "from-env", "EA_AD_BIND_PASSWORD": "bind-env"}
	getenv := func(k string) string { return env[k] }

	file := EA{Password: "file-pw", AD: EAActiveDirectory{BindPassword: "file-bind"}}

	kept := keepEnvOnlyEASecrets(file, EA{Password: "from-env", AD: EAActiveDirectory{BindPassword: "bind-env"}}, getenv)
	require.Equal(t, "file-pw", kept.Password)
	require.Equal(t, "file-bind", kept.AD.BindPassword)

	changed := keepEnvOnlyEASecrets(file, EA{Password: "typed", AD: EAActiveDirectory{BindPassword: "typed-bind"}}, getenv)
	require.Equal(t, "typed", changed.Password)
	require.Equal(t, "typed-bind", changed.AD.BindPassword)

	noEnv := keepEnvOnlyEASecrets(file, EA{Password: "x"}, func(string) string { return "" })
	require.Equal(t, "x", noEnv.Password)
}
