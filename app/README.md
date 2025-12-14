# Build
Use `make build`. This especially compiles the protobuf files used by the python server.

## requirements
### packages
You can install the protobuf compiler with the following command:
`sudo apt-get update && sudo apt-get install protobuf-compiler`

### update path variable
The following should be within your `$PATH`: `$(go env GOPATH)/bin`



# GRPC example
_this example may be outdated, but can be adapted_

in `grpc/`, execute Make to generate the python files (this should have happened with `make build`)

## Server
execute `grpc/server.py`

## Emulate Client 
_this example is outdated, but can be adapted_

```
grpcurl \
  -plaintext \
  -d '{"data": "040000350000012cb2e84fd00800000000000000000020078ce471076e6fcf8a8cbce7d3ef876bd01c1caeccded1fa1e722ffe3946821b000016"}' \
  localhost:50051 Tls13Parser.TlsParser.Handshake
```
