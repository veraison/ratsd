# RATSD

A RATS conceptual message collection daemon 

# Building

## Prerequisites

Before building RATSD, you need to install the following system dependencies:

### Protocol Buffer Compiler (protoc)

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y protobuf-compiler
```

**RHEL/CentOS/Fedora:**
```bash
# For RHEL/CentOS
sudo yum install -y protobuf-compiler
# For Fedora
sudo dnf install -y protobuf-compiler
```

**macOS:**
```bash
brew install protobuf
```

**From Source (if package not available):**
```bash
# Download and install protoc from https://github.com/protocolbuffers/protobuf/releases
# Example for Linux x86_64:
curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v25.1/protoc-25.1-linux-x86_64.zip
unzip protoc-25.1-linux-x86_64.zip -d $HOME/.local
export PATH="$PATH:$HOME/.local/bin"
```

### Go Dependencies

The binary `ratsd` is built by using `make` using the following steps:
* Install golang version specified in go.mod
* Ensure GOPATH is available in the shell path (`export GOPATH="$HOME/go"; export PATH=$PATH:$GOPATH/bin`)
* Install build tools using `make install-tools`.
* Build RATSd using `make`

## (Optional) Regenerate ratsd core code from OpenAPI spec
Regeneration of the code for ratsd requires the installation of protobuf compiler and Go protobuf plugins. 

**Prerequisites:** Make sure you have installed the `protoc` compiler (see Prerequisites section above).

Then install the Go code generation tools:
```bash
make install-tools
```

Generate the code:
```bash
make generate
```

**Note:** The `make install-tools` command installs:
- `protoc-gen-go` - Go protocol buffer plugin
- `protoc-gen-go-grpc` - Go gRPC plugin  
- `oapi-codegen` - OpenAPI code generator
- `mockgen` - Mock generation tool

All of these require the base `protoc` compiler to be installed separately.

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
curl -X POST http://localhost:8895/ratsd/chares -H "Content-type: application/vnd.veraison.chares+json" -d '{"nonce": "TUlEQk5IMjhpaW9pc2pQeXh4eHh4eHh4eHh4eHh4eHhNSURCTkgyOGlpb2lzalB5eHh4eHh4eHh4eHh4eHh4eA", tsm-report:{"privilege_level": "$level"}}' # Replace $level with a number from 0 to 3
```
### Get evidence from the selected attester only

If more than one leaf attesters present, ratsd adds the evidence generated by all attesters to the response of `/ratsd/chares`. To limit the output to the selected attester, add `list-options: selected` to config.yaml,
 then specify the name of each attester along with the associated options in `attester-selection`. If the user does not wish to specify the attester-specific option, "$attester_name": "null" should be specified. The following is an example of the request:
```
"nonce": "base64urlencoded",

"attester-selection": {
  "attester-id-1": {
    "param11name": "param11value",
    "param12name": "param12value"
  },
  "attester-id-2": {
    "param21name": "param21value"
  },
  "attester-id-3": null
}
```

If `list-options` is not set, or if it's set to `all` in config.yaml, ratsd populates the EAT with CMW from all available attesters as the default behavior.
### Content type selection

Pick the desired output content type of each sub-attester
by specifying field "content-type" in "attester-selection" as shown in
the following example:
```json
"attester-selection": {
    "mock-tsm":{
        "content-type": "application/vnd.veraison.configfs-tsm+json",
        "privilege_level": "3"
    }
}
```

## Mock Mode for Development and Testing

RATSD includes a mock mode that allows you to serve pre-defined evidence for early end-to-end testing without requiring real attesters or hardware. This is particularly useful for:

- Development and integration testing
- CI/CD pipeline validation  
- Testing with specific evidence scenarios
- Demonstrating RATSD functionality

### Running RATSD in Mock Mode

To start RATSD in mock mode, use the `mock` subcommand:

```bash
./ratsd mock --evidence examples/mock/simple-mock-tsm.json
```

### Mock Evidence File Format

Mock evidence files use JSON format with the following structure:

```json
{
  "attesters": {
    "attester-name": {
      "content_type": "application/vnd.veraison.content-type",
      "evidence": "base64-encoded-evidence-data"
    }
  }
}
```

### Example Files

RATSD provides several example mock evidence files:

- `examples/mock/simple-mock-tsm.json` - Single TSM attester evidence
- `examples/mock/multi-attester-evidence.json` - Multiple attesters (TSM + ARM CCA)
- `examples/mock/arm-cca-evidence.json` - ARM CCA attester evidence

### Using Mock Mode

1. **Start the mock server:**
   ```bash
   ./ratsd mock --evidence examples/mock/simple-mock-tsm.json
   ```

2. **Query evidence (same API as normal mode):**
   ```bash
   curl -X POST http://localhost:8895/ratsd/chares \
     -H "Content-Type: application/vnd.veraison.chares+json" \
     -d '{"nonce":"dGVzdC1ub25jZS0xMjM0NTY3ODkwYWJjZGVm"}'
   ```

3. **Query available attesters:**
   ```bash
   curl http://localhost:8895/ratsd/subattesters
   ```

### Creating Custom Mock Evidence

To create your own mock evidence files:

1. **Determine the evidence format** for your use case
2. **Base64 encode** the evidence data
3. **Create a JSON file** following the format above
4. **Test with RATSD** using the mock mode

Example:
```json
{
  "attesters": {
    "my-custom-attester": {
      "content_type": "application/my-custom-format",
      "evidence": "eyJjdXN0b21fZGF0YSI6InRlc3QifQ=="
    }
  }
}
```

The mock mode serves the pre-loaded evidence for any nonce, making it ideal for predictable testing scenarios.
