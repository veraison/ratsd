# RATSD

A RATS conceptual message collection daemon 

# Building
The binary ratsd is built by using make using the following steps:
- Install golang version specified in go.mod
- Ensure GOPATH is available in the shell path (export GOPATH="$HOME/go"; export PATH=$PATH:$GOPATH/bin)
- Build RATSd using make
## (Optional) Regenerate ratsd core code from OpenAPI spec
Regenerate the generated ratsd core code after changing the OpenAPI spec with:
```bash
make generate
```

## Building ratsd core and leaf attesters

Use the 'make build' command to build both the ratsd core and the leaf attesters. To build only the ratsd core, run `make build-la`. Run `make build-sa` to build only the leaf attesters.
```console
$ make build
go build -o ratsd -buildmode=pie ./cmd
make -C attesters/
make[1]: Entering directory '/builddir/build/BUILD/ratsd-1.0.3+la3/attesters'
make -C tsm
make[2]: Entering directory '/builddir/build/BUILD/ratsd-1.0.3+la3/attesters/tsm'
make -C plugin
make[3]: Entering directory '/builddir/build/BUILD/ratsd-1.0.3+la3/attesters/tsm/plugin'
CGO_ENABLED=1 go build  -o ../../bin/tsm.plugin
make[3]: Leaving directory '/builddir/build/BUILD/ratsd-1.0.3+la3/attesters/tsm/plugin'
make[2]: Leaving directory '/builddir/build/BUILD/ratsd-1.0.3+la3/attesters/tsm'
make -C mocktsm
make[2]: Entering directory '/builddir/build/BUILD/ratsd-1.0.3+la3/attesters/mocktsm'
make -C plugin
make[3]: Entering directory '/builddir/build/BUILD/ratsd-1.0.3+la3/attesters/mocktsm/plugin'
CGO_ENABLED=1 go build  -o ../../bin/mocktsm.plugin
make[3]: Leaving directory '/builddir/build/BUILD/ratsd-1.0.3+la3/attesters/mocktsm/plugin'
make[2]: Leaving directory '/builddir/build/BUILD/ratsd-1.0.3+la3/attesters/mocktsm'
make[1]: Leaving directory '/builddir/build/BUILD/ratsd-1.0.3+la3/attesters'
```

### NVIDIA GPU attester prerequisites

The `nvgpu` attester supports NVIDIA Hopper and Blackwell GPUs with confidential computing enabled. The attester host must have a compatible NVIDIA driver installed; the driver provides the `libnvidia-ml.so.1` NVML library that the plugin loads at runtime. Containerized deployments must expose the NVIDIA devices and driver libraries to the container.

# Configuration

RATSD's local `config` package adapts the configuration handling from
[veraison/services](https://github.com/veraison/services/tree/v0.0.2501/config).
It uses Viper to read configuration and mapstructure and govalidator to load
and validate component settings. The services dependency is still used for logging.

Run `./ratsd -c /path/to/config.yaml` (or `--config`) to choose a configuration
file. The default is `config.yaml` in the current working directory. `-h` /
`--help` prints usage, and `-v` / `--version` prints the build version without
loading configuration. Set the version when building with
`go build -ldflags '-X github.com/veraison/ratsd/config.Version=1.0.3' -o ratsd ./cmd`.

The `ratsd` section is required; `logging` and `auth` are optional. The supplied
`config.yaml` is a working HTTP example. HTTPS requires both `cert` and
`cert-key`. Enabling `secure-loader` also requires a `plugins` section mapping
plugin names to SHA-256 checksums.

For components using the package:

- `ReadRawConfig(path, allowNotFound)` reads an explicit file, inferring its
  format from its extension, or searches for `config.yaml` when the path is empty.
  `allowNotFound` permits missing files but still reports invalid configuration.
  The raw Viper retains services' `VERAISON_` environment prefix, with uppercase
  dotted keys such as `VERAISON_RATSD.PROTOCOL`. Viper subtrees do not inherit
  this automatic environment lookup.
- `GetSubs(source, "ratsd", "*logging")` extracts component sections. Prefixing
  a name with `*` makes it optional and returns an empty Viper if it is absent.
- `NewLoader(&settings)` loads from a map or Viper into a struct. Nonzero field
  values supply defaults; `config:"zerodefault"` permits zero-valued defaults.
  Missing and unknown directives are errors. `NewNonExclusiveLoader` allows
  unknown directives, and `mapstructure:",remain"` captures backend settings.
- `mapstructure` tags map directive names to fields, `valid` tags validate field
  formats, and an optional `Validate() error` method checks additional constraints.

# Query ratsd

By default, ratsd core listens on port 8895. Use `POST /ratsd/chares` to retrieve a CMW collection containing evidence from each sub-attester. This API call requires the request body to be the JSON object `{"nonce": $(Base64 string of 64-byte data)}` replacing the placeholder with a proper base64 string. See the following example:
```bash
$ curl -X POST http://localhost:8895/ratsd/chares -H "Content-type: application/vnd.veraison.chares+json" -d '{"nonce": "TUlEQk5IMjhpaW9pc2pQeXh4eHh4eHh4eHh4eHh4eHhNSURCTkgyOGlpb2lzalB5eHh4eHh4eHh4eHh4eHh4eA"}' 
{"cmw":"eyJfX2Ntd2NfdCI6InRhZzpnaXRodWIuY29tLDIwMjU6dmVyYWlzb24vcmF0c2QvY213IiwibW9jay10c20iOlsiYXBwbGljYXRpb24vdm5kLnZlcmFpc29uLmNvbmZpZ2ZzLXRzbStqc29uIiwiZXlKaGRYaGliRzlpSWpvaVdWaFdORmx0ZUhaWlp5SXNJbTkxZEdKc2IySWlPaUpqU0Vwd1pHMTRiR1J0Vm5OUGFVRjNRMjFzZFZsdGVIWlphbTluVGtkUk1FOVVVVEJPUkVrd1dsUlJORTE2U1hwUFJGazFUbXByTWxwcVdUVk9lazB5V1ZSVmQwNTZhek5QUkdNMFRucG5NMDlFWXpST2VtY3pUMFJqTkU1Nlp6TlBSR00wVG5wbk0wOUVZelJPZW1jelQwUlNhMDVFYXpCT1JGRjVUa2RWTUU5RVRYbE5lbWN5VDFSWk5VNXRXVEpQVkdONlRtMUZNVTFFWXpWT2VtY3pUMFJqTkU1Nlp6TlBSR00wVG5wbk0wOUVZelJPZW1jelQwUmpORTU2WnpOUFJHTTBUbnBuSWl3aWNISnZkbWxrWlhJaU9pSm1ZV3RsWEc0aWZRIl19","eat_nonce":"TUlEQk5IMjhpaW9pc2pQeXh4eHh4eHh4eHh4eHh4eHhNSURCTkgyOGlpb2lzalB5eHh4eHh4eHh4eHh4eHh4eA","eat_profile":"tag:github.com,2024:veraison/ratsd"}
```
## Get available attesters
Use endpoint `GET /ratsd/subattesters` to query all available leaf attesters and their available options. The usage can be found in the following
```console
$ curl http://localhost:8895/ratsd/subattesters
[{"name":"mock-tsm","options":[{"data-type":"string","name":"privilege_level"}]},{"name":"tsm-report","options":[{"data-type":"string","name":"privilege_level"}]}]
```
## Complex queries

Ratsd currently supports the Trusted Secure Module `tsm` attester. You can specify the `privilege_level` for configfs-TSM in the query.
```bash
curl -X POST http://localhost:8895/ratsd/chares -H "Content-type: application/vnd.veraison.chares+json" -d '{"nonce": "TUlEQk5IMjhpaW9pc2pQeXh4eHh4eHh4eHh4eHh4eHhNSURCTkgyOGlpb2lzalB5eHh4eHh4eHh4eHh4eHh4eA", "tsm-report":{"privilege_level":"1"}}'
```
### Get evidence from the selected attester only

If more than one leaf attester is present, ratsd returns evidence from all available attesters in the response to `/ratsd/chares` by default. To limit the response to specific attesters, include `attester-selection` in the request body and list the desired attester names there. If an attester has options, specify them in a top-level field named after the attester. If an attester has no options, simply omit the top-level field for that attester. The following is an example request:
```json
{
  "nonce": "base64urlencoded",
  "attester-selection": [
    "attester-id-1",
    "attester-id-2",
    "attester-id-3"
  ],
  "attester-id-1": {
    "param11name": "param11value",
    "param12name": "param12value"
  },
  "attester-id-2": {
    "param21name": "param21value"
  }
}
```

If `list-options: selected` is set in `config.yaml`, `attester-selection` is required and must contain at least one attester. If `list-options` is not set, or is set to `all`, omitting `attester-selection` returns evidence from all available attesters, while providing it limits the response to the selected attesters only.
### Content type selection

Pick the desired output content type of each sub-attester
by specifying field "content-type" in the top-level attester field as shown in
the following example:
```json
"attester-selection": [
    "mock-tsm"
],
"mock-tsm": {
    "content-type": "application/vnd.veraison.tsm-report+json",
    "privilege_level": "3"
}
```
