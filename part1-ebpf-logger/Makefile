COMPOSE      ?= docker compose
SVC_LOGGER   ?= packet-logger
SVC_WIRESHARK ?= wireshark
CTR_LOGGER   := ebpf-packet-logger
CTR_WIRESHARK := ebpf-wireshark
OUTPUT_DIR   ?= output
TRAFFIC      ?= all

export HOST_UID := $(shell id -u)
export HOST_GID := $(shell id -g)

.DEFAULT_GOAL := help

.PHONY: help up up-d down logs logs-logger logs-wireshark status test decode \
        view-log view-decoded clean fix-perms rebuild

help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

up:
	$(COMPOSE) up --build

up-d:
	$(COMPOSE) up --build -d
	@echo "Running in background. View logs: make logs   |   Stop: make down"

down:
	@if docker ps --format '{{.Names}}' | grep -q '^$(CTR_WIRESHARK)$$'; then \
		if [ -s $(OUTPUT_DIR)/capture.pcap ]; then \
			echo "==> Decoding $(OUTPUT_DIR)/capture.pcap -> $(OUTPUT_DIR)/decoded.txt ..."; \
			docker exec $(CTR_WIRESHARK) tshark -r /work/output/capture.pcap -V \
				> $(OUTPUT_DIR)/decoded.txt 2>&1 \
				&& echo "    Wrote $$(wc -l < $(OUTPUT_DIR)/decoded.txt) lines." \
				|| echo "    tshark decode failed (see $(OUTPUT_DIR)/decoded.txt)."; \
		else \
			echo "==> No capture.pcap to decode (empty or missing)."; \
		fi \
	else \
		echo "==> $(CTR_WIRESHARK) not running; skipping explicit decode."; \
	fi
	$(COMPOSE) down
	@$(MAKE) --no-print-directory fix-perms
	@-ip link del veth0 2>/dev/null || true
	@-ip link del veth1 2>/dev/null || true

logs:
	$(COMPOSE) logs -f

logs-logger:
	$(COMPOSE) logs -f $(SVC_LOGGER)

logs-wireshark:
	$(COMPOSE) logs -f $(SVC_WIRESHARK)

status:
	$(COMPOSE) ps

test:
	docker exec $(CTR_LOGGER) /work/scripts/send-traffic.sh $(TRAFFIC)

decode:
	@if [ ! -s $(OUTPUT_DIR)/capture.pcap ]; then \
		echo "output/capture.pcap is empty or missing. Is the demo running? Try: make up"; \
		exit 1; \
	fi
	@if [ "$(WRITE)" = "1" ]; then \
		echo "==> Writing $(OUTPUT_DIR)/decoded.txt ..."; \
		docker exec $(CTR_WIRESHARK) tshark -r /work/output/capture.pcap \
			$(if $(FILTER),-Y $(FILTER),) -V > $(OUTPUT_DIR)/decoded.txt; \
		echo "    $$(wc -l < $(OUTPUT_DIR)/decoded.txt) lines written."; \
	else \
		docker exec $(CTR_WIRESHARK) tshark -r /work/output/capture.pcap \
			$(if $(FILTER),-Y $(FILTER),) -V; \
	fi

view-log:
	@cat $(OUTPUT_DIR)/packets.log 2>/dev/null || echo "No packets.log yet. Start the demo: make up"

view-decoded:
	@cat $(OUTPUT_DIR)/decoded.txt 2>/dev/null || echo "No decoded.txt yet. It's written on 'make down', or run: make decode WRITE=1"

clean:
	$(COMPOSE) down -v
	@$(MAKE) --no-print-directory fix-perms
	rm -rf $(OUTPUT_DIR)/packets.log $(OUTPUT_DIR)/capture.pcap $(OUTPUT_DIR)/decoded.txt
	@-ip link del veth0 2>/dev/null || true
	@-ip link del veth1 2>/dev/null || true

fix-perms:
	@echo "==> chown output/ -> $(HOST_UID):$(HOST_GID)"
	@docker run --rm -v "$(CURDIR)/$(OUTPUT_DIR):/work/output" \
		alpine:latest chown -R "$(HOST_UID):$(HOST_GID)" /work/output

rebuild:
	$(COMPOSE) build --no-cache
