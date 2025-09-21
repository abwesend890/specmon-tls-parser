default: build

build:
	python -m grpc_tools.protoc -I./grpc/protos --pyi_out=grpc --python_out=grpc --grpc_python_out=grpc ./grpc/protos/tls13.proto

test:
	grpcurl -plaintext -proto grpc/protos/tls13.proto -d '{"data": "040000350000012cb2e84fd00800000000000000000020078ce471076e6fcf8a8cbce7d3ef876bd01c1caeccded1fa1e722ffe3946821b0000"}' localhost:50051 TlsParser.TlsParser.SayHello
