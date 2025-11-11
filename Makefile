# Makefile for Assignment 3 (Ubuntu 24.04.3 LTS)
# Usage:
#   make all
#   make run              # run test_audit with audit_logger.so preloaded
#   make monitor-s        # show suspicious users
#   make monitor-file F=example.txt
#
# Notes:
#   - All logs are stored in the current working directory (access_audit.log)

CC = gcc
CFLAGS = -Wall -Wextra -Wno-unused-result -O2 -fPIC -shared
LIBS = -ldl -lcrypto

# Default log path (local, not /tmp)
LOG_PATH ?= $(PWD)/access_audit.log

all: audit_logger.so audit_monitor test_audit

audit_logger.so: audit_logger.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -o $@ $< $(LIBS)

audit_monitor: audit_monitor.c
	$(CC) -Wall -Wextra -O2 -o $@ $<

test_audit: test_audit.c
	$(CC) -Wall -Wextra -O2 -o $@ $<

# --- Convenience targets ---

run: audit_logger.so test_audit
	@echo "Running test_audit with audit_logger.so..."
	env AUDIT_LOG_PATH="$(LOG_PATH)" LD_PRELOAD="$(PWD)/audit_logger.so" ./test_audit

monitor-s: audit_monitor
	@echo "Running audit_monitor -s..."
	env AUDIT_LOG_PATH="$(LOG_PATH)" ./audit_monitor -s

monitor-file: audit_monitor
	@if [ -z "$(F)" ]; then \
		echo "Usage: make monitor-file F=example.txt"; \
		exit 1; \
	fi
	@echo "Running audit_monitor -i $(PWD)/$(F)..."
	env AUDIT_LOG_PATH="$(LOG_PATH)" ./audit_monitor -i "$(PWD)/$(F)"

clean:
	rm -f audit_logger.so audit_monitor test_audit
	rm -f access_audit.log example*.txt no_perm.txt noaccess_*.txt
	@echo "Cleanup completed."
