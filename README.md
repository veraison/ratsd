# RATSD

A RATS conceptual message collection daemon 

# Building
The binary `ratsd` is built by using `make` using the following steps:
* Install golang version specified in go.mod
* Ensure GOPATH is available in the shell path (`export GOPATH="$HOME/go"; export PATH=$PATH:$GOPATH/bin`)
* Install build tools using `make install-tools`.
* Build RATSd using `make`

## (Optional) Regenerate ratsd core code from OpenAPI spec
Regeneration of the code for ratsd requires the installation of various protobuf packages beforehand. Use the following commands to install them:
```bash
make install-tools
```
Then generate the code with `make generate`
## Building ratsd core and leaf attesters
Use `make build` to build both ratsd core and the leaf attests. To build only the ratsd core, please run `make build-la`. Run `build-sa` to build only the leaf attesters.
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
By default ratsd core listens to port `8895`, use the API `POST /ratsd/chares` to get a CMW collection containing the evidence from each sub-attester. This API requires the body to be a JSON-like string `{"nonce": $(Base64 string of 64-byte data)}`, replace $(Base64 string of 64-byte data) with a proper base64 string. See the following example:
```bash
$ curl -X POST http://localhost:8895/ratsd/chares -H "Content-type: application/vnd.veraison.chares+json" -d '{"nonce": "TUlEQk5IMjhpaW9pc2pQeXh4eHh4eHh4eHh4eHh4eHhNSURCTkgyOGlpb2lzalB5eHh4eHh4eHh4eHh4eHh4eA"}' 
{"cmw":"eyJfX2Ntd2NfdCI6InRhZzpnaXRodWIuY29tLDIwMjU6dmVyYWlzb24vcmF0c2QvY213IiwibW9jay10c20iOlsiYXBwbGljYXRpb24vdm5kLnZlcmFpc29uLmNvbmZpZ2ZzLXRzbStqc29uIiwiZXlKaGRYaGliRzlpSWpvaVdWaFdORmx0ZUhaWlp5SXNJbTkxZEdKc2IySWlPaUpqU0Vwd1pHMTRiR1J0Vm5OUGFVRjNRMjFzZFZsdGVIWlphbTluVGtkUk1FOVVVVEJPUkVrd1dsUlJORTE2U1hwUFJGazFUbXByTWxwcVdUVk9lazB5V1ZSVmQwNTZhek5QUkdNMFRucG5NMDlFWXpST2VtY3pUMFJqTkU1Nlp6TlBSR00wVG5wbk0wOUVZelJPZW1jelQwUlNhMDVFYXpCT1JGRjVUa2RWTUU5RVRYbE5lbWN5VDFSWk5VNXRXVEpQVkdONlRtMUZNVTFFWXpWT2VtY3pUMFJqTkU1Nlp6TlBSR00wVG5wbk0wOUVZelJPZW1jelQwUmpORTU2WnpOUFJHTTBUbnBuSWl3aWNISnZkbWxrWlhJaU9pSm1ZV3RsWEc0aWZRIl19","eat_nonce":"TUlEQk5IMjhpaW9pc2pQeXh4eHh4eHh4eHh4eHh4eHhNSURCTkgyOGlpb2lzalB5eHh4eHh4eHh4eHh4eHh4eA","eat_profile":"tag:github.com,2024:veraison/ratsd"}
```
## Complex queries
Ratsd currently support `tsm` (Trusted Secure Module) attester. It's possible to specify the `privilege_level` for configfs-TSM in the query
```bash
curl -X POST http://localhost:8895/ratsd/chares -H "Content-type: application/vnd.veraison.chares+json" -d '{"nonce": "TUlEQk5IMjhpaW9pc2pQeXh4eHh4eHh4eHh4eHh4eHhNSURCTkgyOGlpb2lzalB5eHh4eHh4eHh4eHh4eHh4eA", tsm-report:{"privilege_level": "$level"}}' # Replace $level with a number from 0 to 3
```
