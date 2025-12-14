default: build

install-environment:
	pipenv install

shell:
	@echo "\033[0;32mEntering environment. Type 'exit' to leave...\033[0m"
	pipenv shell | true

build-python-server: install-environment
	@echo "\033[0;32mbuilding python grpc files...\033[0m"
	pipenv run python -m grpc_tools.protoc -I./grpc --pyi_out=python-server --python_out=python-server --grpc_python_out=python-server ./grpc/tls13.proto

build: build-python-server shell

test:
	@pipenv run make start -C python-server/ ; true
	sleep 1
	@make -C client_example/ test
	@pipenv run make stop -C python-server/

test-server-grpcurl-newsessionticket:
	grpcurl -plaintext -d '{"data": "040000350000012cb2e84fd00800000000000000000020078ce471076e6fcf8a8cbce7d3ef876bd01c1caeccded1fa1e722ffe3946821b0000"}' localhost:50051 Tls13Parser.TlsParser.SayHello
