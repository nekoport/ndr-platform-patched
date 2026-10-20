# NDR Platform - operational shortcuts
# Usage: make <target>   (run from repo root; reads .env when present)

S ?= ndr-pipeline

.PHONY: help up down restart status logs ps build backup backup-list restore \
        health sensor sensor-down rule-update rule-status pull shell-os shell-pg

help:
	@echo "NDR Platform targets:"
	@echo "  up / down / restart      base stack lifecycle"
	@echo "  sensor / sensor-down     sensor profile (zeek, suricata, arkime)"
	@echo "  status                   docker compose ps"
	@echo "  logs S=<svc>             follow logs of service"
	@echo "  build                    rebuild images"
	@echo "  health                   run scripts/healthcheck.sh"
	@echo "  backup                   run scripts/backup.sh"
	@echo "  rule-update              refresh Suricata rules + live reload"
	@echo "  rule-status              show loaded rule stats from the sensor"

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

status:
	@bash scripts/healthcheck.sh 2>/dev/null || docker compose ps

logs:
	docker compose logs -f --tail=100 $(S)

ps:
	docker compose ps

build:
	docker compose build

sensor:
	docker compose --profile sensor up -d

# v0.13.0: stop ONLY the sensor services - `--profile sensor down` used to
# take the WHOLE stack (opensearch/postgres/api/ui) down with it
sensor-down:
	docker compose stop zeek suricata arkime

rule-update:
	bash scripts/rule-update.sh

rule-status:
	-docker exec ndr-suricata suricatasc -c ruleset-stats
	docker exec ndr-suricata sh -c 'ls -la /var/lib/suricata/rules/ | head -8; echo; grep -c . /var/lib/suricata/rules/disable.conf 2>/dev/null || echo "disable.conf: empty/none"'

backup:
	bash scripts/backup.sh

health:
	bash scripts/healthcheck.sh

shell-os:
	docker exec -it ndr-opensearch bash

shell-pg:
	docker exec -it ndr-postgres psql -U $$(grep '^POSTGRES_USER=' .env | cut -d= -f2) -d $$(grep '^POSTGRES_DB=' .env | cut -d= -f2)
