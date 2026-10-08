package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

func ReadRawConfig(path string, allowNotFound bool) (*viper.Viper, error) {
	source := viper.New()
	if path != "" {
		source.SetConfigFile(path)
	} else {
		workingDir, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		source.AddConfigPath(workingDir)
		source.SetConfigType("yaml")
		source.SetConfigName("config")
	}

	source.SetEnvPrefix("veraison")
	source.AutomaticEnv()

	err := source.ReadInConfig()
	var notFound viper.ConfigFileNotFoundError
	if allowNotFound && (errors.As(err, &notFound) || errors.Is(err, os.ErrNotExist)) {
		err = nil
	}
	return source, err
}

func GetSubs(source *viper.Viper, names ...string) (map[string]*viper.Viper, error) {
	if source == nil {
		return nil, ErrNilConfig
	}

	var missing []string
	subs := make(map[string]*viper.Viper)
	for _, name := range names {
		optional := strings.HasPrefix(name, "*")
		name = strings.TrimPrefix(name, "*")
		sub := source.Sub(name)
		if sub == nil {
			if optional {
				subs[name] = viper.New()
			} else {
				missing = append(missing, name)
			}
		} else {
			subs[name] = sub
		}
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing directives in %s: %s",
			source.ConfigFileUsed(), strings.Join(missing, ", "))
	}
	return subs, nil
}
