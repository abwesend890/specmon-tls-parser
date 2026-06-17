# TLS Parser Service via gRPC server
This project exposes a gGRPC server on `127.0.0.1:50051`.
The server provides the `Tls13Parser.Generic`service with the request name `Parse`.
Also it provides the `Tls13Parser.Specific` with the request name `ParseHelloRetryRequest` and `GetKeyShareExtension`

ParseHelloRetryRequest` exists as dedicated function as the generic scapy function failed to successfully parse this message kind.

See Marcos in https://github.com/abwesend890/CryptoTrack/blob/main/spthy/monitor_tls13.spthy to get more context.

## Easy use with docker compose
Run `docker compose up`

## Start the server without docker
- Run `make` to start the server in foreground mode.
- Run `make detached` to start the server in background mode.

## Stop the server without docker
- If executed in foreground mode, use `CTRL+C`.
- Run `make down` to stop the server.
