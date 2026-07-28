# part2-postgres-sink - host-side orchestration.
#
# Mirrors part1-ebpf-logger/Makefile but targets the postgres demo. Only ever
# calls `docker compose` / `docker exec` — never invokes cmake or the compiler
# directly. The build happens inside the capture container at startup:
#
#   host:      make up            (this Makefile)
#   container: capture-entrypoint.sh
#   container: cmake -> clang (BPF) + gcc (loader)
#
# The in-container build and this top-level Makefile don't interact.

# ---- Config -------------------------------------------------------------
COMPOSE        ?= docker compose
SVC_CAPTURE    ?= capture
SVC_WIRESHARK  ?= wireshark
SVC_POSTGRES   ?= postgres
CTR_CAPTURE    := bpf-pg-capture
CTR_WIRESHARK  := bpf-pg-wireshark
CTR_POSTGRES   := bpf-postgres
OUTPUT_DIR     ?= output
DB             := ${POSTGRES_DB:-packets}
USER           := ${POSTGRES_USER:-packets}

# Export host uid/gid so containers chown their output artifacts back to us.
# This is what lets you `rm output/*` without "Permission denied" afterwards.
export HOST_UID := $(shell id -u)
export HOST_GID := $(shell id -g)

.DEFAULT_GOAL := help

# ---- Targets ------------------------------------------------------------
.PHONY: help up up-d demo down logs logs-capture logs-wireshark logs-pg status \
        traffic decode view-capture view-decoded sql psql query \
        clean fix-perms rebuild nuke

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

up: ## Start postgres + capture + wireshark in the foreground (Ctrl-C to stop).
	$(COMPOSE) up --build

up-d: ## Start postgres + capture + wireshark detached (background).
	$(COMPOSE) up --build -d
	@echo "Running in background. View logs: make logs   |   Stop: make down"

demo: ## One-shot: up -> generate traffic -> show SQL -> decode -> down.
	@echo "=========================================="
	@echo "  Postgres XDP capture - one-shot demo"
	@echo "=========================================="
	@# 1. Start the stack detached.
	@echo "==> [1/5] Starting services..."
	@$(COMPOSE) up --build -d >/dev/null 2>&1
	@# 2. Wait for the capture service to be ready (postgres healthy + XDP attached).
	@echo "==> [2/5] Waiting for capture service to attach XDP..."
	@for i in $$(seq 1 60); do \
		if docker logs $(CTR_CAPTURE) 2>&1 | grep -q "Streaming capture"; then \
			break; \
		fi; \
		sleep 1; \
	done
	@# 3. Generate traffic.
	@echo "==> [3/5] Generating Postgres traffic (7 queries)..."
	@$(COMPOSE) run --rm db-client >/dev/null 2>&1 || true
	@sleep 1
	@# 4. Show captured SQL.
	@echo "==> [4/5] Captured SQL queries:"
	@docker exec $(CTR_WIRESHARK) tshark -r /work/output/pg_capture.pcap \
		-Y pgsql.query -T fields -e pgsql.query 2>/dev/null \
		| sed 's/^/    /' || echo "    (no queries captured)"
	@# 5. Decode full pcap and shut down.
	@echo "==> [5/5] Decoding pg_capture.pcap -> pg_decoded.txt and shutting down..."
	@$(MAKE) --no-print-directory down >/dev/null 2>&1
	@echo ""
	@echo "Done. Artifacts:"
	@echo "    $(OUTPUT_DIR)/pg_capture.pcap  ($$(stat -c %s $(OUTPUT_DIR)/pg_capture.pcap 2>/dev/null || echo 0) bytes)"
	@echo "    $(OUTPUT_DIR)/pg_decoded.txt   ($$(stat -c %s $(OUTPUT_DIR)/pg_decoded.txt 2>/dev/null || echo 0) bytes)"
	@echo ""
	@echo "View the queries again:  make sql    (needs stack running)"
	@echo "                        grep -A1 'Statement:' $(OUTPUT_DIR)/pg_decoded.txt"

down: ## Stop services; decode pg_capture.pcap -> pg_decoded.txt before shutdown.
	@# 1. Stop the capture service FIRST so the pcap is fully flushed.
	@#    (If we decode while capture is still writing, we get a partial pcap.)
	@if docker ps --format '{{.Names}}' | grep -q '^$(CTR_CAPTURE)$$'; then \
		echo "==> Stopping capture (flushing pcap)..."; \
		$(COMPOSE) stop capture >/dev/null 2>&1 || true; \
	fi
	@# 2. Decode using the wireshark sidecar (still running). Write to a temp
	@#    file then rename, so a failure never corrupts a prior good decode.
	@if docker ps --format '{{.Names}}' | grep -q '^$(CTR_WIRESHARK)$$'; then \
		if [ -s $(OUTPUT_DIR)/pg_capture.pcap ]; then \
			echo "==> Decoding $(OUTPUT_DIR)/pg_capture.pcap -> $(OUTPUT_DIR)/pg_decoded.txt ..."; \
			docker exec $(CTR_WIRESHARK) bash -c \
				'tshark -r /work/output/pg_capture.pcap -V 2>/dev/null > /work/output/pg_decoded.txt.tmp && \
				 mv -f /work/output/pg_decoded.txt.tmp /work/output/pg_decoded.txt' \
				&& echo "    Wrote $$(wc -l < $(OUTPUT_DIR)/pg_decoded.txt) lines." \
				|| { echo "    tshark decode failed."; rm -f $(OUTPUT_DIR)/pg_decoded.txt.tmp; }; \
		else \
			echo "==> No pg_capture.pcap to decode (empty or missing)."; \
		fi \
	else \
		echo "==> $(CTR_WIRESHARK) not running; skipping decode."; \
	fi
	@# 3. Now bring everything down. The wireshark sidecar's EXIT trap will
	@#    re-decode, but the atomic temp+rename means it can't corrupt the
	@#    file we just wrote.
	$(COMPOSE) down

logs: ## Tail logs from all services.
	$(COMPOSE) logs -f

logs-capture: ## Tail only the XDP capture service.
	$(COMPOSE) logs -f $(SVC_CAPTURE)

logs-wireshark: ## Tail only the tshark sidecar.
	$(COMPOSE) logs -f $(SVC_WIRESHARK)

logs-pg: ## Tail only postgres.
	$(COMPOSE) logs -f $(SVC_POSTGRES)

status: ## Show container status.
	$(COMPOSE) ps

traffic: ## Run the one-shot db-client (runs a few queries to generate traffic).
	$(COMPOSE) run --rm db-client

decode: ## Decode current XDP pcap to stdout (WRITE=1 saves to output/pg_decoded.txt; FILTER="pgsql").
	@if [ ! -s $(OUTPUT_DIR)/pg_capture.pcap ]; then \
		echo "output/pg_capture.pcap is empty or missing. Is the demo running? Try: make up"; \
		exit 1; \
	fi
	@if [ "$(WRITE)" = "1" ]; then \
		echo "==> Writing $(OUTPUT_DIR)/pg_decoded.txt ..."; \
		docker exec $(CTR_WIRESHARK) tshark -r /work/output/pg_capture.pcap \
			$(if $(FILTER),-Y $(FILTER),) -V > $(OUTPUT_DIR)/pg_decoded.txt; \
		echo "    $$(wc -l < $(OUTPUT_DIR)/pg_decoded.txt) lines written."; \
	else \
		docker exec $(CTR_WIRESHARK) tshark -r /work/output/pg_capture.pcap \
			$(if $(FILTER),-Y $(FILTER),) -V; \
	fi

view-capture: ## Show capture_loader's packet count summary (tail of capture logs).
	@docker logs --tail 5 $(CTR_CAPTURE) 2>/dev/null || echo "No capture container running."

view-decoded: ## Show the full tshark decode (output/pg_decoded.txt).
	@cat $(OUTPUT_DIR)/pg_decoded.txt 2>/dev/null || echo "No pg_decoded.txt yet. It's written on 'make down', or run: make decode WRITE=1"

sql: ## List all SQL queries captured (tshark -Y pgsql.query). Needs running wireshark.
	@if [ ! -s $(OUTPUT_DIR)/pg_capture.pcap ]; then \
		echo "output/pg_capture.pcap is empty or missing. Is the demo running? Try: make up"; \
		exit 1; \
	fi
	@if ! docker ps --format '{{.Names}}' | grep -q '^$(CTR_WIRESHARK)$$'; then \
		echo "$(CTR_WIRESHARK) not running. Start with: make up"; \
		exit 1; \
	fi
	@echo "=== SQL queries in $(OUTPUT_DIR)/pg_capture.pcap ==="
	@docker exec $(CTR_WIRESHARK) tshark -r /work/output/pg_capture.pcap \
		-Y pgsql.query -T fields -e pgsql.query 2>/dev/null \
		| sed 's/^/  /'

psql: ## Connect to the packets DB inside the postgres container with psql.
	@docker exec -it $(CTR_POSTGRES) psql -U $(USER) -d $(DB)

# Example: make query SQL='SELECT count(*) FROM demo;'
query: ## Run a SQL statement (SQL='...') and print the result.
	@test -n "$(SQL)" || { echo "Usage: make query SQL='SELECT ...'"; exit 1; }
	@docker exec $(CTR_POSTGRES) psql -U $(USER) -d $(DB) -c "$(SQL)"

clean: ## Stop services and remove output artifacts (keeps source + pgdata).
	$(COMPOSE) down
	@# Artifacts may be root-owned from a prior run; chown via a throwaway
	@# root container so the rm below never hits "Permission denied".
	@$(MAKE) --no-print-directory fix-perms
	rm -rf $(OUTPUT_DIR)/pg_capture.pcap $(OUTPUT_DIR)/pg_decoded.txt

nuke: ## Stop services AND delete the pgdata volume (fresh DB next `make up`).
	$(COMPOSE) down -v

fix-perms: ## Reown output/* to the current host user (fixes root-owned files).
	@echo "==> chown output/ -> $(HOST_UID):$(HOST_GID)"
	@docker run --rm -v "$(CURDIR)/$(OUTPUT_DIR):/work/output" \
		alpine:latest chown -R "$(HOST_UID):$(HOST_GID)" /work/output

rebuild: ## Force a clean rebuild of the Docker images.
	$(COMPOSE) build --no-cache