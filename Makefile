LOGGER := part1-ebpf-logger
PG     := part2-postgres-sink

.DEFAULT_GOAL := help

.PHONY: help \
        log-up log-up-d log-down log-logs log-test log-rebuild \
        pg-up pg-up-d pg-down pg-logs pg-traffic pg-psql pg-rebuild \
        rebuild-all down-all

help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

log-up:
	$(MAKE) -C $(LOGGER) up

log-up-d:
	$(MAKE) -C $(LOGGER) up-d

log-down:
	$(MAKE) -C $(LOGGER) down

log-logs:
	$(MAKE) -C $(LOGGER) logs

log-test:
	$(MAKE) -C $(LOGGER) test

log-rebuild:
	$(MAKE) -C $(LOGGER) rebuild

pg-up:
	$(MAKE) -C $(PG) up

pg-up-d:
	$(MAKE) -C $(PG) up-d

pg-down:
	$(MAKE) -C $(PG) down

pg-logs:
	$(MAKE) -C $(PG) logs

pg-traffic:
	$(MAKE) -C $(PG) traffic

pg-psql:
	$(MAKE) -C $(PG) psql

pg-rebuild:
	$(MAKE) -C $(PG) rebuild

rebuild-all: log-rebuild pg-rebuild

down-all: log-down pg-down
