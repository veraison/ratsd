# RATSD Configuration

This package adapts the configuration handling from
[veraison/services](https://github.com/veraison/services/tree/v0.0.2501/config).
RATSD uses [Viper](https://github.com/spf13/viper) to collect configuration.
The loader adds validation so that components receive complete, valid settings
before they start using them. Runtime configuration options are documented in
the [main README](../README.md#configuration).

## The General Idea

- Each component defines its configuration as a struct.
- The component passes a pointer to a struct instance to the loader. Existing
  field values can provide defaults.
- Viper collects configuration, and `Sub()` selects the portion belonging to
  the component.
- `LoadFromViper()` loads that component's settings using Viper's
  `AllSettings()`. `LoadFromMap()` accepts a `map[string]interface{}` directly.
- The loader decodes the settings, validates field constraints, and calls the
  struct's `Validate() error` method if one is defined.
- After loading succeeds, the component can use the validated struct.

## Validation

The loader checks that:

- Values can be decoded into the destination field types. Convertible values,
  such as numeric strings for integer fields, are accepted.
- Every field has a supplied value or a default. A missing field without a
  default is an error.
- All supplied directives are recognized. This catches misspelled or unused
  settings. Pass only the component's configuration to the loader, or use
  `NewNonExclusiveLoader()` when additional directives should be allowed.
- Fields satisfy any constraints in their `valid` tags. Supported validators
  are described in the
  [govalidator README](https://github.com/asaskevich/govalidator#validators).
- Any additional constraints implemented by the struct's `Validate() error`
  method are satisfied. This method can check relationships between settings.

## Field names in configuration

The loader uses [mapstructure](https://github.com/mitchellh/mapstructure) to
decode settings into a struct. Names are matched case-insensitively using
`strings.EqualFold`. Use a `mapstructure` tag when a directive's name differs
from its field name, for example when it contains a hyphen:

```go
type Config struct {
	HyphenatedSetting string `mapstructure:"hyphenated-setting"`
}
```

## Handling of Defaults

A component can supply its own defaults by setting fields before passing the
configuration struct to `NewLoader()`. Supplied configuration values override
these defaults.

Code that initializes a component can instead use `SetDefault()` on the Viper
instance passed to that component. This lets the caller provide defaults
without changing the component's configuration struct.

### Zero-values in Defaults

A struct field's zero value cannot distinguish an unset field from an intended
default. The loader therefore treats zero-valued fields as unset unless they
have a `config:"zerodefault"` tag:

```go
type Config struct {
	MustBeSet  string
	CanBeEmpty string `config:"zerodefault"`
	CanBeZero  int    `config:"zerodefault"`
}
```

An explicit zero value in the input is considered supplied, even without the
tag. Field validators and `Validate()` still apply to supplied and defaulted
values.

## Example

This example loads settings from a map and applies an additional validation
rule. Use `LoadFromViper()` instead when the settings come from a Viper instance.

```go
package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/veraison/ratsd/config"
)

type Config struct {
	Host string
	Port uint16
}

func (settings Config) Validate() error {
	if settings.Port == 0 {
		return errors.New("port must be nonzero")
	}
	return nil
}

func main() {
	var settings Config
	loader := config.NewLoader(&settings)

	err := loader.LoadFromMap(map[string]interface{}{
		"host": "example.com",
		"port": 8443,
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s:%d\n", settings.Host, settings.Port)
}
```

## Build version

As in [services](https://github.com/veraison/services/blob/main/mk/cmd.mk),
`Version` in `buildtime.go` remains `N/A` for builds without linker flags.
The root Makefile runs `scripts/get-ratsd-version` and injects its output with
`-X github.com/veraison/ratsd/config.Version=...` when building the daemon.

The helper follows services' tag-plus-commit format, removing the tag's leading
`v`. It selects the latest `v[0-9]*` tag in version order and appends the short
HEAD commit. Repositories without version tags use `0.0.0+<commit>`; builds
without Git or repository metadata use `0.0.0-unknown`. `RATSD_BUILD_VERSION`
overrides detection, corresponding to services' `VERAISON_BUILD_VERSION`.
