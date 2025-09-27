default: init build

init:
	@echo "\033[0;32minitializing go module...\033[0m"
	go mod init go-tls-parser-client || true
build:
	@echo "\033[0;32mbuilding go module...\033[0m"
	go mod tidy
test: build
	@echo "\033[0;32mexecuting client test...\033[0m"
	@echo "\033[0;33m"
	@go run ../client-tests/example.go
	@echo "\033[0m"

clean:
	rm go.mod
	rm go.sum
