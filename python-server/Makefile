# Define the file to store the process ID
PIDFILE = server.pid

.PHONY: start stop status

default: start

# Target to start the server in the background
start: 
	@if [ -f $(PIDFILE) ]; then \
		echo "Server is already running with PID: $$(cat $(PIDFILE))"; \
		exit 1; \
	fi
	@echo "Starting server..."
	@python server.py > server.log & echo $$! > $(PIDFILE)
	@echo "Server started with PID: $$(cat $(PIDFILE))"

# Target to stop the server
stop:
	@if [ -f $(PIDFILE) ]; then \
       	        echo "Stopping server..."; \
		kill $$(cat $(PIDFILE)); \
		rm $(PIDFILE); \
		echo "Server stopped."; \
	else \
		echo "Server not running (or PID file not found)."; \
	fi

status:
	@if [ -f $(PIDFILE) ]; then \
		echo "Server is running with PID: $$(cat $(PIDFILE))"; \
	else \
		echo "Server is not running."; \
	fi
