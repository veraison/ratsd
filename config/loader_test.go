package config

import (
	"errors"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type serverSettings struct {
	Address  string `mapstructure:"listen-addr" valid:"dialstring"`
	Protocol string `valid:"in(http|https)"`
	Cert     string `config:"zerodefault"`
	Enabled  bool   `config:"zerodefault"`
}

func (settings serverSettings) Validate() error {
	if settings.Protocol == "https" && settings.Cert == "" {
		return errors.New("HTTPS requires a certificate")
	}
	return nil
}

func TestLoaderLoadFromMap(test *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected serverSettings
		err      string
	}{
		{
			name:     "defaults",
			expected: serverSettings{Address: "localhost:8895", Protocol: "http"},
		},
		{
			name: "overrides and weak typing",
			input: map[string]interface{}{
				"listen-addr": "127.0.0.1:9000", "protocol": "https", "cert": "server.crt", "enabled": "true",
			},
			expected: serverSettings{Address: "127.0.0.1:9000", Protocol: "https", Cert: "server.crt", Enabled: true},
		},
		{
			name: "unknown directive", input: map[string]interface{}{"typo": true},
			err: "unexpected directives: typo",
		},
		{
			name: "invalid field", input: map[string]interface{}{"listen-addr": "not an address"},
			err: "does not validate as dialstring",
		},
		{
			name: "invalid protocol", input: map[string]interface{}{"protocol": "ftp"},
			err: "does not validate as in(http|https)",
		},
		{
			name: "custom validation", input: map[string]interface{}{"protocol": "https"},
			err: "HTTPS requires a certificate",
		},
		{
			name: "invalid type", input: map[string]interface{}{"enabled": "not a boolean"},
			err: "cannot parse 'Enabled' as bool",
		},
	}
	for _, testCase := range tests {
		test.Run(testCase.name, func(test *testing.T) {
			settings := serverSettings{Address: "localhost:8895", Protocol: "http"}
			err := NewLoader(&settings).LoadFromMap(testCase.input)
			if testCase.err != "" {
				require.ErrorContains(test, err, testCase.err)
				return
			}
			require.NoError(test, err)
			assert.Equal(test, testCase.expected, settings)
		})
	}
}

func TestLoaderRequiredAndZeroValues(test *testing.T) {
	settings := struct {
		Count    int
		Optional string `config:"zerodefault"`
	}{}
	loader := NewLoader(&settings)
	require.ErrorContains(test, loader.LoadFromMap(nil), "directives not found: Count")
	require.NoError(test, loader.LoadFromMap(map[string]interface{}{"count": 0}))
	assert.Zero(test, settings.Count)
	assert.Empty(test, settings.Optional)
}

func TestLoaderUnknownAndRemainingSettings(test *testing.T) {
	input := map[string]interface{}{
		"backend": "basic", "users": map[string]interface{}{"alice": "hash"},
	}
	settings := struct{ Backend string }{}
	require.ErrorContains(test, NewLoader(&settings).LoadFromMap(input), "unexpected directives: users")
	require.NoError(test, NewNonExclusiveLoader(&settings).LoadFromMap(input))
	assert.Equal(test, "basic", settings.Backend)

	backend := struct {
		Backend string                 `mapstructure:"backend,omitempty"`
		Options map[string]interface{} `mapstructure:",remain"`
	}{}
	require.NoError(test, NewLoader(&backend).LoadFromMap(input))
	assert.Equal(test, "basic", backend.Backend)
	assert.Equal(test, input["users"], backend.Options["users"])
}

func TestLoaderLoadFromViper(test *testing.T) {
	settings := serverSettings{Address: "localhost:8895", Protocol: "http"}
	loader := NewLoader(&settings)
	require.ErrorIs(test, loader.LoadFromViper(nil), ErrNilConfig)

	source := viper.New()
	source.SetEnvPrefix("test")
	source.AutomaticEnv()
	source.SetDefault("listen-addr", "localhost:9000")
	test.Setenv("TEST_LISTEN-ADDR", "localhost:9001")
	require.NoError(test, loader.LoadFromViper(source))
	assert.Equal(test, "localhost:9001", settings.Address)
}

func TestLoaderInvalidDestination(test *testing.T) {
	var nilSettings *serverSettings
	for _, dest := range []interface{}{nil, nilSettings, 7, serverSettings{}} {
		var loader Loader
		require.Error(test, loader.Init(dest))
		assert.Panics(test, func() { NewLoader(dest) })
		assert.Panics(test, func() { NewNonExclusiveLoader(dest) })
	}
}
