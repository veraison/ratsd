# RATSD

A RATS conceptual message collection daemon 

# Building

Building requires a number of tools to be installed before `make` will successfully run.

## Prerequisites

### Mockgen

Go's `mockgen` is required and needs to be on the PATH. Installation details can be found here https://github.com/golang/mock

### Protobuf

Protobuf packages to be installed - some distributions, eg: Debian 12, do not include these.

```console
sudo apt-get -y install protoc-gen-go
sudo apt-get -y install protoc-gen-go-grpc
```

## Build

To build run `make`. Typical output will be as folows

```console
ian@Debian:~/ratsd$ make
go generate ./...
make -C attesters/
make[1]: Entering directory '/home/ian/ratsd/attesters'
make -C tsm
make[2]: Entering directory '/home/ian/ratsd/attesters/tsm'
make -C plugin
make[3]: Entering directory '/home/ian/ratsd/attesters/tsm/plugin'
CGO_ENABLED=1 go build  -o ../../bin/tsm.plugin
make[3]: Leaving directory '/home/ian/ratsd/attesters/tsm/plugin'
make[2]: Leaving directory '/home/ian/ratsd/attesters/tsm'
make -C mocktsm
make[2]: Entering directory '/home/ian/ratsd/attesters/mocktsm'
make -C plugin
make[3]: Entering directory '/home/ian/ratsd/attesters/mocktsm/plugin'
CGO_ENABLED=1 go build  -o ../../bin/mocktsm.plugin
make[3]: Leaving directory '/home/ian/ratsd/attesters/mocktsm/plugin'
make[2]: Leaving directory '/home/ian/ratsd/attesters/mocktsm'
make[1]: Leaving directory '/home/ian/ratsd/attesters'
go build -o ratsd -buildmode=pie ./cmd
ian@Debian:~/ratsd$ ls -l ratsd
-rwxr-xr-x 1 ian ian 27587543 Apr 25 10:47 ratsd
```

