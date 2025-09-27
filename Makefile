default: build

prepare_environment:
	@echo "\033[0;32mpreparing environment...\033[0m"
	pipenv install
	pipenv shell | true

build-python-server: prepare_environment 
	@echo "\033[0;32mbuilding python grpc files...\033[0m"
	python -m grpc_tools.protoc -I./grpc/protos --pyi_out=grpc --python_out=grpc --grpc_python_out=grpc ./grpc/protos/tls13.proto

build-go-client:
	@echo "\033[0;32mbuilding go grpc files...\033[0m"
	protoc --go_out=./go-client --go-grpc_out=./go-client ./grpc/protos/tls13.proto
	make -C go-client/

build: build-python-server build-go-client

test:
	grpcurl -plaintext -proto grpc/protos/tls13.proto -d '{"data": "040000350000012cb2e84fd00800000000000000000020078ce471076e6fcf8a8cbce7d3ef876bd01c1caeccded1fa1e722ffe3946821b0000"}' localhost:50051 TlsParser.TlsParser.SayHello
