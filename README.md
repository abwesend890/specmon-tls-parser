# TLS Parser Service via gRPC server
This project exposes a gGRPC server on `127.0.0.1:50051`.
The server provides the `Tls13Parser.TlsParser` service.
The service includes the methods
- `Parse`
- `ParseHelloRetryRequest`

`ParseHelloRetryRequest` exists as dedicated function as the generic scapy function failed to successfully parse this message kind.

## Start the server
- Run `make` to start the server in foreground mode.
- Run `make detached` to start the server in background mode.

## Stop the server
- If executed in foreground mode, use `CTRL+C`.
- Run `make down` to stop the server.
