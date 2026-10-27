# RATSD

A RATS conceptual message collection daemon 

# Building
The binary ratsd is built by using make using the following steps:
- Install golang version specified in go.mod
- Ensure GOPATH is available in the shell path (export GOPATH="$HOME/go"; export PATH=$PATH:$GOPATH/bin)
- Build RATSd using make

RATSD uses the standalone [ratsd-token](https://github.com/veraison/ratsd-token)
modules for legacy JSON and v2 CBOR/COSE attestation tokens, plus TSM reports and
NVIDIA GPU evidence formats. Both module versions are pinned in `go.mod` and
downloaded by Go during the build.

## (Optional) Regenerate ratsd core code from OpenAPI spec
Regenerate the generated ratsd core code after changing the OpenAPI spec with:
```bash
make generate
```

## Building ratsd core and leaf attesters

Use the 'make build' command to build both the ratsd core and the leaf attesters. To build only the ratsd core, run `make build-la`. Run `make build-sa` to build only the leaf attesters.

`make build` and `make build-la` set the version reported by `./ratsd --version`
from the latest `v`-prefixed version tag and the current Git commit, for example
`0.0.1+7c81383`. To override it, including when building a source archive, set
`RATSD_BUILD_VERSION`:

```bash
RATSD_BUILD_VERSION=1.0.3 make build-la
```

Without Git metadata, the version defaults to `0.0.0-unknown`.

```console
$ make build
go build -o ratsd -buildmode=pie -ldflags "-X 'github.com/veraison/ratsd/config.Version=0.0.1+7c81383'" ./cmd
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

Run `./ratsd -c /path/to/config.yaml` (or `--config`) to choose a configuration
file. The default is `config.yaml` in the current working directory. `-h` /
`--help` prints usage, and `-v` / `--version` prints the build version without
loading configuration.

The `ratsd` section is required. The supplied [config.yaml](config.yaml) is a
working HTTP example. Available settings within `ratsd` are:

| Setting | Default | Description |
| --- | --- | --- |
| `listen-addr` | `localhost:8895` | Address and port to listen on. |
| `protocol` | `https` | `http` or `https`. |
| `cert` | Empty | TLS certificate file; required for HTTPS. |
| `cert-key` | Empty | TLS private key file; required for HTTPS. |
| `plugin-dir` | Must be supplied | Directory containing the attester `.plugin` executables. |
| `list-options` | Must be supplied | `all` allows requests without attester selection; `selected` requires it. |
| `secure-loader` | `false` | Verify plugin SHA-256 checksums before loading them. |

When `secure-loader` is enabled, also supply a top-level `plugins` section
mapping plugin names to hexadecimal SHA-256 checksums.

The `logging` and `auth` sections are optional. See the
[logging options](log/README.md) for log levels, formats, and destinations.
`auth.backend` defaults to `passthrough`; `none` also disables authentication.
For HTTP Basic authentication, set `auth.backend` to `basic` and supply bcrypt
password hashes under `auth.users.<username>.password`.

Runtime settings must be supplied in the configuration file. Environment
variables such as `VERAISON_RATSD.PROTOCOL` do not currently override these
settings. `RATSD_BUILD_VERSION` controls the build version as described above;
it does not change an already-built binary.

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
[{"name":"mock-tsm","options":[{"data-type":"string","name":"privilege_level"}]},{"name":"tsm-report","options":[{"data-type":"string","name":"privilege_level"},{"data-type":"string","name":"service_provider"},{"data-type":"string","name":"service_guid"}]}]
```
## Complex queries

Ratsd currently supports the Trusted Secure Module `tsm` attester. You can specify the `privilege_level` for configfs-TSM in the query.
```bash
curl -X POST http://localhost:8895/ratsd/chares -H "Content-type: application/vnd.veraison.chares+json" -d '{"nonce": "TUlEQk5IMjhpaW9pc2pQeXh4eHh4eHh4eHh4eHh4eHhNSURCTkgyOGlpb2lzalB5eHh4eHh4eHh4eHh4eHh4eA", "tsm-report":{"privilege_level":"1"}}'
```

To request SVSM attestation on a host with configfs-TSM SVSM support, set `service_provider` to `"svsm"`:
```bash
curl -X POST http://localhost:8895/ratsd/chares -H "Content-type: application/vnd.veraison.chares+json" -d '{"nonce": "TUlEQk5IMjhpaW9pc2pQeXh4eHh4eHh4eHh4eHh4eHhNSURCTkgyOGlpb2lzalB5eHh4eHh4eHh4eHh4eHh4eA", "attester-selection":["tsm-report"], "tsm-report":{"service_provider":"svsm"}}'
```
The TSM evidence includes `service_provider: "svsm"` and the `manifestblob` returned by SVSM, alongside the report and any SEV-SNP certificate table. These fields are supported in both JSON and CBOR output; JSON encodes the manifest as unpadded base64url. The `provider` output continues to identify the hardware report format (for example, `sev_guest`). Omitting `service_provider` uses the default hardware attestation path.

Selecting `"svsm"` without `service_guid` requests attestation for all active SVSM services, including vTPM when present. The plugin leaves the configfs `service_guid` attribute unset, preserving the null-GUID default that selects `SVSM_ATTEST_SERVICES` ([Linux configfs-TSM ABI](https://www.kernel.org/doc/Documentation/ABI/testing/configfs-tsm)).

To select a service, supply `service_guid` alongside `service_provider`. For example, the following options select vTPM:
```json
"tsm-report": {
  "service_provider": "svsm",
  "service_guid": "c476f1eb-0123-45a5-9641-b4e7dde5bfe3"
}
```
The GUID is passed unchanged to configfs. Linux validates it and determines the report and manifest contents; the plugin does not restrict GUIDs to a known list or interpret the returned blobs. A non-null GUID selects `SVSM_ATTEST_SINGLE_SERVICE`; an explicit `00000000-0000-0000-0000-000000000000` selects all services. The vTPM GUID above returns its service manifest rather than the all-services manifest ([SVSM specification, sections 7.2 and 8.3.1](https://docs.amd.com/v/u/en-US/58019.pdf)). A `service_guid` option without `service_provider` is rejected.

SVSM attestation uses `SVSM_ATTEST_SERVICES` or `SVSM_ATTEST_SINGLE_SERVICE` to obtain a VMPL0 report that binds the requested manifest, as specified in [sections 7.1 and 7.2 of the SVSM specification](https://docs.amd.com/v/u/en-US/58019.pdf). Omit `privilege_level` when selecting `"svsm"`: SVSM requests the VMPL0 report on behalf of the guest, even when the guest runs at a higher-numbered VMPL. The `privilege_level` option selects the report VMPL on the default hardware attestation path; it does not select the VMPL of an SVSM report. An explicitly supplied `privilege_level` is still validated by configfs, so setting it to `"0"` can fail when the guest's `privlevel_floor` is greater than zero.

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

If `list-options: selected` is set in `config.yaml`, `attester-selection` is required and must contain at least one attester. If `list-options: all` is set, omitting `attester-selection` returns evidence from all available attesters, while providing it limits the response to the selected attesters only.
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
