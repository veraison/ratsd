package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadRawConfig(test *testing.T) {
	for _, testCase := range []struct {
		name string
		data string
	}{
		{name: "config.yaml", data: "ratsd:\n  protocol: http\n"},
		{name: "config.json", data: `{"ratsd":{"protocol":"http"}}`},
		{name: "config.toml", data: "[ratsd]\nprotocol = 'http'\n"},
	} {
		test.Run(testCase.name, func(test *testing.T) {
			path := filepath.Join(test.TempDir(), testCase.name)
			require.NoError(test, os.WriteFile(path, []byte(testCase.data), 0600))
			source, err := ReadRawConfig(path, false)
			require.NoError(test, err)
			assert.Equal(test, "http", source.GetString("ratsd.protocol"))
			assert.Equal(test, path, source.ConfigFileUsed())
			test.Setenv("VERAISON_RATSD.PROTOCOL", "https")
			assert.Equal(test, "https", source.GetString("ratsd.protocol"))
		})
	}
}

func TestReadRawConfigDefaultPath(test *testing.T) {
	test.Chdir(test.TempDir())
	require.NoError(test, os.WriteFile("config.yaml", []byte("ratsd:\n  protocol: http\n"), 0600))
	source, err := ReadRawConfig("", false)
	require.NoError(test, err)
	assert.Equal(test, "http", source.GetString("ratsd.protocol"))
}

func TestReadRawConfigMissingFile(test *testing.T) {
	test.Chdir(test.TempDir())
	for _, path := range []string{"", "missing.yaml"} {
		_, err := ReadRawConfig(path, false)
		require.Error(test, err)
		source, err := ReadRawConfig(path, true)
		require.NoError(test, err)
		require.NotNil(test, source)
		assert.Empty(test, source.AllSettings())
	}
}

func TestReadRawConfigInvalidFile(test *testing.T) {
	path := filepath.Join(test.TempDir(), "config.yaml")
	require.NoError(test, os.WriteFile(path, []byte("ratsd: ["), 0600))
	for _, allowNotFound := range []bool{false, true} {
		_, err := ReadRawConfig(path, allowNotFound)
		require.Error(test, err)
	}
	_, err := ReadRawConfig(test.TempDir(), true)
	require.Error(test, err)
}

func TestGetSubs(test *testing.T) {
	source := viper.New()
	source.SetConfigFile("test-config.yaml")
	source.Set("ratsd.protocol", "http")
	source.Set("logging", map[string]interface{}{})

	subs, err := GetSubs(source, "ratsd", "*logging", "*auth")
	require.NoError(test, err)
	require.Len(test, subs, 3)
	assert.Equal(test, "http", subs["ratsd"].GetString("protocol"))
	assert.NotNil(test, subs["logging"])
	require.NotNil(test, subs["auth"])
	assert.Empty(test, subs["auth"].AllSettings())

	subs, err = GetSubs(source, "ratsd", "auth", "plugins")
	assert.Nil(test, subs)
	assert.EqualError(test, err, "missing directives in test-config.yaml: auth, plugins")

	subs, err = GetSubs(nil, "ratsd")
	assert.Nil(test, subs)
	assert.ErrorIs(test, err, ErrNilConfig)
}
