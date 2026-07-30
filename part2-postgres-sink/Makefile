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

export HOST_UID := $(shell id -u)
export HOST_GID := $(shell id -g)

.DEFAULT_GOAL := help

.PHONY: help up up-d demo down logs logs-capture logs-wireshark logs-pg status \
        traffic decode view-capture view-decoded sql psql query \
        clean fix-perms rebuild nuke

help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

up:
	$(COMPOSE) up --build

up-d:
	$(COMPOSE) up --build -d
	@echo "Running in background. View logs: make logs   |   Stop: make down"

demo:
	@echo "=========================================="
	@echo "  Postgres XDP capture - one-shot demo"
	@echo "=========================================="
	@echo "==> [1/5] Starting services..."
	@$(COMPOSE) up --build -d >/dev/null 2>&1
	@echo "==> [2/5] Waiting for capture service to attach XDP..."
	@for i in $$(seq 1 60); do \
		if docker logs $(CTR_CAPTURE) 2>&1 | grep -q "Streaming capture"; then \
			break; \
		fi; \
		sleep 1; \
	done
	@echo "==> [3/5] Generating Postgres traffic (7 queries)..."
	@$(COMPOSE) run --rm db-client >/dev/null 2>&1 || true
	@sleep 1
	@echo "==> [4/5] Captured SQL queries:"
	@docker exec $(CTR_WIRESHARK) tshark -r /work/output/pg_capture.pcap \
		-Y pgsql.query -T fields -e pgsql.query 2>/dev/null \
		| sed 's/^/    /' || echo "    (no queries captured)"
	@echo "==> [5/5] Decoding pg_capture.pcap -> pg_decoded.txt and shutting down..."
	@$(MAKE) --no-print-directory down >/dev/null 2>&1
	@echo ""
	@echo "Done. Artifacts:"
	@echo "    $(OUTPUT_DIR)/pg_capture.pcap  ($$(stat -c %s $(OUTPUT_DIR)/pg_capture.pcap 2>/dev/null || echo 0) bytes)"
	@echo "    $(OUTPUT_DIR)/pg_decoded.txt   ($$(stat -c %s $(OUTPUT_DIR)/pg_decoded.txt 2>/dev/null || echo 0) bytes)"
	@echo ""
	@echo "View the queries again:  make sql    (needs stack running)"
	@echo "                        grep -A1 'Statement:' $(OUTPUT_DIR)/pg_decoded.txt"

down:
	@if docker ps --format '{{.Names}}' | grep -q '^$(CTR_CAPTURE)$$'; then \
		echo "==> Stopping capture (flushing pcap)..."; \
		$(COMPOSE) stop capture >/dev/null 2>&1 || true; \
	fi
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
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f

logs-capture:
	$(COMPOSE) logs -f $(SVC_CAPTURE)

logs-wireshark:
	$(COMPOSE) logs -f $(SVC_WIRESHARK)

logs-pg:
	$(COMPOSE) logs -f $(SVC_POSTGRES)

status:
	$(COMPOSE) ps

traffic:
	$(COMPOSE) run --rm db-client

decode:
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

view-capture:
	@docker logs --tail 5 $(CTR_CAPTURE) 2>/dev/null || echo "No capture container running."

view-decoded:
	@cat $(OUTPUT_DIR)/pg_decoded.txt 2>/dev/null || echo "No pg_decoded.txt yet. It's written on 'make down', or run: make decode WRITE=1"

sql:
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

psql:
	@docker exec -it $(CTR_POSTGRES) psql -U $(USER) -d $(DB)

query:
	@test -n "$(SQL)" || { echo "Usage: make query SQL='SELECT ...'"; exit 1; }
	@docker exec $(CTR_POSTGRES) psql -U $(USER) -d $(DB) -c "$(SQL)"

clean:
	$(COMPOSE) down
	@$(MAKE) --no-print-directory fix-perms
	rm -rf $(OUTPUT_DIR)/pg_capture.pcap $(OUTPUT_DIR)/pg_decoded.txt

nuke:
	$(COMPOSE) down -v

fix-perms:
	@echo "==> chown output/ -> $(HOST_UID):$(HOST_GID)"
	@docker run --rm -v "$(CURDIR)/$(OUTPUT_DIR):/work/output" \
		alpine:latest chown -R "$(HOST_UID):$(HOST_GID)" /work/output

rebuild:
	$(COMPOSE) build --no-cache
