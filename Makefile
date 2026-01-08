.PHONY: install dev test lint format typecheck docker-build docker-up docker-down clean

# Install dependencies
install:
	uv sync

# Install with dev dependencies
install-dev:
	uv sync --group lint --group test

# Run development server
dev:
	uv run uvicorn main:app --reload --host 0.0.0.0 --port 8000

test:
	uv run --group test pytest tests/ -v

lint:
	uv run --group lint ruff check .

format:
	uv run --group lint ruff format .
	uv run --group lint ruff check --fix .

typecheck:
	uv run --group lint mypy main.py

docker-build:
	docker build -t webhook-to-agentbuilder .

docker-up:
	docker compose up -d

docker-down:
	docker compose down

clean:
	rm -rf __pycache__ .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
