# GRPC example
in `grpc/`, execute Make to generate the python files

## Server
execute `grpc/server.py`

## Emulate Client 
```
grpcurl \
  -plaintext \
  -proto protos/test.proto \
  -d '{"name": "grpcurl client"}' \
  localhost:50051 \
  greeter.Greeter.SayHello
{
  "message": "Hello, grpcurl client! Greetings from Python."
}
```