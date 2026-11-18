.DEFAULT_GOAL := help
COMPOSE ?= docker compose
VENV ?= .venv

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup: ## Create .env from the example
	@test -f .env || cp .env.example .env

up: setup ## Build and start Void (no keys or Tor Browser needed)
	$(COMPOSE) up -d --build

up-local: setup ## Same, plus an optional local Ollama model (~5 GB)
	$(COMPOSE) --profile local-llm up -d --build

down: ## Stop the stack (add --profile local-llm to also stop Ollama)
	$(COMPOSE) --profile local-llm down

logs: ## Follow app logs
	$(COMPOSE) logs -f app

install: ## Create a local virtualenv with dev dependencies
	python3 -m venv $(VENV) && $(VENV)/bin/pip install -r requirements-dev.txt

run: ## Run locally (needs only the `tor` package: sudo apt install tor)
	DATA_DIR=$${DATA_DIR:-./data} \
	$(VENV)/bin/uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000

test: ## Run the test suite
	$(VENV)/bin/python -m pytest

lint: ## Lint with ruff
	$(VENV)/bin/ruff check . && $(VENV)/bin/ruff format --check .

fmt: ## Auto-format with ruff
	$(VENV)/bin/ruff check --fix . && $(VENV)/bin/ruff format .

.PHONY: help setup up up-local down logs install run test lint fmt
