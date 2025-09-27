default: init build
init:
	@echo "\033[0;32minitializing go module...\033[0m"
	go mod init go-client || true
build:
	@echo "\033[0;32mbuilding go module...\033[0m"
	go mod tidy
run: build
	go run client.go
