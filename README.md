# RATSD

A RATS conceptual message collection daemon 

# Building
The binary `ratsd` is built by using `make` using the following steps:
* Install golang version specified in go.mod
* Ensure GOPATH is available in the shell path (```export GOPATH="$HOME/go"; export PATH=$PATH:$GOPATH/bin```)
* Install build tools using ```make install-tools```.
* Build RATSd using ```make```

## Debian 12

Compilation requires various protobuf packages to be installed before

```bash
sudo apt-get -y install protoc-gen-go
sudo apt-get -y install protoc-gen-go-grpc
```

Building is started using `make` and will also run various tests. After successful compilation the binary `ratsd` should be present, for example:

```console
$ make
go generate ./...
go build -o ratsd -buildmode=pie ./cmd
go test -v github.com/veraison/ratsd/api
=== RUN   TestRatsdChares_missing_auth_header
2025-02-27T15:55:40.807+0200	ERROR	test	api/server.go:32	wrong or missing authorization header
github.com/veraison/ratsd/api.(*Server).reportProblem
	/home/ian/ratsd/api/server.go:32
...
...
...
--- PASS: TestRatsdChares_missing_nonce (0.00s)
=== RUN   TestRatsdChares_valid_request
2025-02-27T15:55:40.807+0200	INFO	test	api/server.go:69	request media type: application/eat+jwt; eat_profile="tag:github.com,2024:veraison/ratsd"
2025-02-27T15:55:40.807+0200	INFO	test	api/server.go:93	request nonce: MIDBNH28iioisjPy
--- PASS: TestRatsdChares_valid_request (0.00s)
PASS
ok  	github.com/veraison/ratsd/api	(cached)
$ ls -l ratsd
-rwxr-xr-x 1 ian ian 17903454 Feb 27 16:03 ratsd
```
