# =============================================================================
#  Chrono-DNS
# =============================================================================
.DEFAULT_GOAL := help
SHELL := /bin/bash
PY    := python3
VENV  := .venv
BIN   := $(VENV)/bin

CYAN  := \033[36m
BOLD  := \033[1m
DIM   := \033[2m
RESET := \033[0m

.PHONY: help setup install init dataset train evade ablate replay live serve \
        dashboard demo bench report hunt test lint format clean reset \
        docker-up docker-down docker-logs healthcheck postgres

help: ## show this help
	@printf "\n$(BOLD)Chrono-DNS$(RESET) — ML-driven DNS security gateway\n\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-16s$(RESET) %s\n", $$1, $$2}'
	@printf "\n$(DIM)first time?  make setup && make demo$(RESET)\n\n"

setup: ## full bootstrap: venv, deps, database, first model
	@bash scripts/setup.sh

install: ## install dependencies into the current environment
	$(PY) -m pip install -r requirements.txt
	$(PY) -m pip install -e ".[dev,web]"

init: ## create schema, indexes, views and seed threat intel
	$(PY) -m chronodns init --reset

dataset: ## generate a labelled synthetic capture
	$(PY) -m chronodns dataset --out data/capture.csv --evasive 200

train: ## train the RF + Isolation Forest ensemble
	$(PY) -m chronodns train --harden

evade: ## adversarial hard-mode evaluation
	$(PY) -m chronodns evade --count 300

ablate: ## feature-group ablation study
	$(PY) -m chronodns ablate

replay: ## replay the capture through the inline pipeline
	$(PY) -m chronodns replay --data data/capture.csv --fresh

live: ## animated SOC console
	$(PY) -m chronodns live

serve: ## run the inline DNS gateway on 127.0.0.1:5353
	$(PY) -m chronodns serve

dashboard: ## web dashboard on http://127.0.0.1:8088
	$(PY) -m chronodns dashboard

demo: ## run the whole pipeline end to end
	@bash scripts/demo.sh --fast

bench: ## throughput benchmark sweep
	@bash scripts/bench.sh

report: ## SOC report from the database
	$(PY) -m chronodns report

hunt: ## threat-hunting queries (tunnels, beacons, talkers)
	$(PY) -m chronodns hunt tunnels
	$(PY) -m chronodns hunt beacons

healthcheck: ## verify every moving part
	@bash scripts/healthcheck.sh

attack: ## fire simulated attacks at a running gateway
	@bash scripts/attack_sim.sh 127.0.0.1 5353 all

test: ## run the test suite
	$(PY) -m pytest -v

test-fast: ## run tests, skipping the slow ones
	$(PY) -m pytest -v -m "not slow"

coverage: ## test suite with coverage report
	$(PY) -m pytest --cov=chronodns --cov-report=term-missing --cov-report=html

lint: ## ruff + mypy
	-$(PY) -m ruff check chronodns tests
	-$(PY) -m mypy chronodns --ignore-missing-imports

format: ## auto-fix lint issues
	$(PY) -m ruff check --fix chronodns tests
	$(PY) -m ruff format chronodns tests

postgres: ## provision the PostgreSQL backend
	@bash scripts/init_db.sh --postgres --create-role

docker-up: ## start postgres + gateway + dashboard in containers
	docker compose up -d --build
	@printf "\n  dashboard  http://127.0.0.1:8088\n  gateway    127.0.0.1:5353\n\n"

docker-down: ## stop and remove the containers
	docker compose down -v

docker-logs: ## tail container logs
	docker compose logs -f

clean: ## remove caches and build artefacts
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage

reset: clean ## also drop the database and trained model
	rm -f data/*.db data/*.db-wal data/*.db-shm data/capture.csv
	rm -f models/*.joblib models/model_card.json models/train_report.json
	@printf "  workspace reset. run: make init && make train\n"
