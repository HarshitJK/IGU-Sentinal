.DEFAULT_GOAL := help

# Docker removed the `docker-compose` v1 binary in favour of the `docker compose`
# plugin; hardcoding v1 made every container target fail on a current install.
COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")
PY := .venv/bin/python

.PHONY: help venv build up down logs test test-unit benchmark diode-proof gen-data clean frontend frontend-dev frontend-open frontend-check dashboard

help: ## Show descriptions of all available targets
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@echo "  help           - Show one-line descriptions of all available targets"
	@echo "  build          - Build Docker images using $(COMPOSE) build"
	@echo "  up             - Start containers in background using $(COMPOSE) up -d"
	@echo "  down           - Stop and remove containers and volumes using $(COMPOSE) down -v"
	@echo "  logs           - Tail container logs using $(COMPOSE) logs -f"
	@echo "  venv           - Create .venv and install pinned requirements"
	@echo "  test           - Run full pytest suite (source .venv, pytest -v)"
	@echo "  test-unit      - Run fast unit tests without Docker dependencies (pytest -v)"
	@echo "  diode-proof    - Start stack, run prod-test -> enclave-test ping check, print pass/fail, then stop stack"
	@echo "  benchmark      - Measure sustained flows/sec and end-to-end latency"
	@echo "  gen-data       - Generate labeled datasets from YAML configs into datasets/ directory"
	@echo "  frontend       - Start the Sentinel API and serve live dashboard at http://localhost:8000/dashboard"
	@echo "  frontend-dev   - Start Sentinel API in auto-reload development mode for frontend iteration"
	@echo "  frontend-open  - Open the live dashboard (http://localhost:8000/dashboard) in default web browser"
	@echo "  frontend-check - Validate existence and integrity of frontend HTML dashboard"
	@echo "  clean          - Remove __pycache__, .pytest_cache, and prompt before removing .venv"

venv: ## Create .venv and install pinned requirements
	python3 -m venv .venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -r requirements.txt
	@echo "Virtualenv ready. Run 'make test'."

build: ## Build Docker images
	$(COMPOSE) build

up: ## Start containers in background
	$(COMPOSE) up -d

down: ## Stop and remove containers and volumes
	$(COMPOSE) down -v

logs: ## Tail container logs
	$(COMPOSE) logs -f

test: ## Run full pytest suite with virtualenv activated
	bash -c "source .venv/bin/activate && pytest -v"

test-unit: ## Run fast unit tests without Docker dependencies
	bash -c "source .venv/bin/activate && pytest -v --ignore=tests/test_diode.py --ignore=tests/test_docker_compose.py --ignore=tests/test_docker_compose_static.py --ignore=tests/test_docker_networks.py --ignore=tests/test_traffic_gen_containers.py"

diode-proof: ## Up stack, run prod-test -> enclave-test ping check, print pass/fail, then down
	@echo "Starting containers..."
	$(COMPOSE) up -d
	@sleep 3
	@echo "Testing diode return-path ping (prod-test -> enclave-test)..."
	@if docker exec igusentinel-prod-test ping -c 1 -W 2 igusentinel-enclave-test >/dev/null 2>&1; then \
		echo "diode-proof: FAIL (traffic passed through, diode failed to block)"; \
		$(COMPOSE) down -v; \
		exit 1; \
	else \
		echo "diode-proof: PASS (return traffic blocked by diode iptables)"; \
	fi
	$(COMPOSE) down -v

benchmark: ## Measure sustained flows/sec and end-to-end latency through the pipeline
	bash -c "source .venv/bin/activate && python -m igu_sentinel.benchmark --flows 2000 --repeats 3"

gen-data: ## Run traffic generator against all configs and output to datasets/
	bash -c "source .venv/bin/activate && python -c \"\
from pathlib import Path; \
import json; \
from igu_sentinel.traffic_gen.runner import run_traffic_gen; \
datasets_dir = Path('datasets'); \
datasets_dir.mkdir(exist_ok=True); \
config_dir = Path('igu_sentinel/traffic_gen/config'); \
for yaml_file in sorted(config_dir.glob('*.yaml')): \
    labeled_flows = run_traffic_gen(str(yaml_file)); \
    for item in labeled_flows: \
        tc = item['threat_class']; \
        flow = item['flow']; \
        out_file = datasets_dir / f'{tc}.jsonl'; \
        with open(out_file, 'a') as f: \
            f.write(flow.model_dump_json() + '\n'); \
print('Datasets generated in datasets/:'); \
for p in sorted(datasets_dir.glob('*.jsonl')): \
    print(f'  - {p.name}') \
\""

dashboard: frontend

frontend: ## Start Sentinel API serving live dashboard
	@echo "Starting IGU Sentinel API & Dashboard at http://localhost:8000/dashboard..."
	bash -c "source .venv/bin/activate && uvicorn igu_sentinel.api:app --host 0.0.0.0 --port 8000"

frontend-dev: ## Start API in development mode with hot reload
	@echo "Starting IGU Sentinel API in dev mode (http://localhost:8000/dashboard)..."
	bash -c "source .venv/bin/activate && uvicorn igu_sentinel.api:app --reload --host 0.0.0.0 --port 8000"

frontend-open: ## Open live dashboard in default browser
	@echo "Opening http://localhost:8000/dashboard..."
	@which xdg-open >/dev/null 2>&1 && xdg-open http://localhost:8000/dashboard || \
	 which open >/dev/null 2>&1 && open http://localhost:8000/dashboard || \
	 echo "Could not detect browser opener. Please visit http://localhost:8000/dashboard manually."

frontend-check: ## Check frontend dashboard HTML component integrity
	@echo "Checking frontend dashboard HTML component..."
	@test -f igu_sentinel/api/dashboard.html && echo "✓ igu_sentinel/api/dashboard.html exists" || (echo "✗ Missing dashboard.html" && exit 1)
	@grep -q "WebSocket" igu_sentinel/api/dashboard.html && echo "✓ WebSocket streaming client found" || (echo "✗ Missing WebSocket script" && exit 1)
	@echo "Frontend check passed."

clean: ## Remove __pycache__, .pytest_cache, and prompt before removing .venv
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf .pytest_cache
	@read -p "Remove virtualenv directory (.venv)? [y/N] " confirm && [ "$$confirm" = "y" -o "$$confirm" = "Y" ] && rm -rf .venv || echo "Skipped .venv removal"
