# Root convenience Makefile.
#
# Each subproject has its own Makefile that does the real work. The targets
# here just forward to them so you can drive the whole repo from the root
# without remembering which subdirectory to cd into.
#
# Naming: `log-*` targets forward to part1-ebpf-logger; `pg-*` targets
# forward to part2-postgres-sink. For richer per-part targets (e.g. part1's
# `decode`, part2's `query`), work directly inside the subproject directory.

LOGGER := part1-ebpf-logger
PG     := part2-postgres-sink

.DEFAULT_GOAL := help

.PHONY: help \
        log-up log-up-d log-down log-logs log-test log-rebuild \
        pg-up pg-up-d pg-down pg-logs pg-traffic pg-psql pg-rebuild \
        rebuild-all down-all

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---- part1: eBPF packet logger (log-*) ----------------------------------
log-up: ## Start the logger in the foreground (Ctrl-C to stop).
	$(MAKE) -C $(LOGGER) up

log-up-d: ## Start the logger detached (background).
	$(MAKE) -C $(LOGGER) up-d

log-down: ## Stop the logger.
	$(MAKE) -C $(LOGGER) down

log-logs: ## Tail logger logs.
	$(MAKE) -C $(LOGGER) logs

log-test: ## Send test traffic into the logger (TRAFFIC=all|icmp|udp|tcp|http).
	$(MAKE) -C $(LOGGER) test

log-rebuild: ## Force a clean rebuild of the logger Docker images.
	$(MAKE) -C $(LOGGER) rebuild

# ---- part2: postgres capture (pg-*) -------------------------------------
pg-up: ## Start postgres capture in the foreground.
	$(MAKE) -C $(PG) up

pg-up-d: ## Start postgres capture detached (background).
	$(MAKE) -C $(PG) up-d

pg-down: ## Stop postgres capture (keeps the pgdata volume).
	$(MAKE) -C $(PG) down

pg-logs: ## Tail postgres capture logs.
	$(MAKE) -C $(PG) logs

pg-traffic: ## Run part2's db-client to generate Postgres traffic.
	$(MAKE) -C $(PG) traffic

pg-psql: ## Open a psql shell on the packets DB.
	$(MAKE) -C $(PG) psql

pg-rebuild: ## Force a clean rebuild of part2's Docker images.
	$(MAKE) -C $(PG) rebuild

# ---- both ---------------------------------------------------------------
rebuild-all: log-rebuild pg-rebuild ## Force a clean rebuild of both parts' images.

down-all: log-down pg-down ## Stop both parts.