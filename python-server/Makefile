# Define the file to store the process ID
PIDFILE = server.pid

.PHONY: start stop status

default: start

# Target to start the server in the background
start: 
	@if [ -f $(PIDFILE) ]; then \
		echo "\033[0;31mServer is already running with PID: $$(cat $(PIDFILE))\033[0m"; \
		exit 1; \
	fi
	@echo "\033[0;32mStarting server...\033[0m"
	@python server.py > server.log & echo $$! > $(PIDFILE)
	@echo "\033[0;32mServer started with PID: $$(cat $(PIDFILE))\033[0m"

# Target to stop the server
stop:
	@if [ -f $(PIDFILE) ]; then \
       	        echo "\033[0;32mStopping server...\033[0m"; \
		kill $$(cat $(PIDFILE)); \
		rm $(PIDFILE); \
		echo "\033[0;32mServer stopped.\033[0m"; \
	else \
		echo "\033[0;31mServer not running (or PID file not found).\033[0m"; \
	fi

status:
	@if [ -f $(PIDFILE) ]; then \
		echo "\033[0;32mServer is running with PID: $$(cat $(PIDFILE))\033[0m"; \
	else \
		echo "\033[0;31mServer is not running.\033[0m
	fi
