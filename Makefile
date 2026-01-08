.PHONY: help install install-dev dev test lint format typecheck docker-build docker-up docker-down docker-rebuild rebuild clean

.DEFAULT_GOAL := help

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	uv sync

install-dev: ## Install with dev dependencies
	uv sync --group lint --group test

dev: ## Run development server
	uv run uvicorn main:app --reload --host 0.0.0.0 --port 8000

test: ## Run tests
	uv run --group test pytest tests/ -v

lint: ## Run linter
	uv run --group lint ruff check .

format: ## Format code
	uv run --group lint ruff format .
	uv run --group lint ruff check --fix .

typecheck: ## Run type checker
	uv run --group lint mypy main.py

build: ## Build Docker image
	docker build -t webhook-to-agentbuilder .

rebuild: ## Rebuild and restart container (after git pull)
	docker compose down
	docker compose build --no-cache
	docker compose up -d

up: ## Start Docker container
	docker compose up -d

down: ## Stop Docker container
	docker compose down

clean: ## Clean up cache files
	rm -rf __pycache__ .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
