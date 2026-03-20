.DEFAULT_GOAL := help

.PHONY: install lint typecheck test scan help

install: ## Install dependencies and download spaCy model
	uv sync
	uv run python -m spacy download en_core_web_lg

lint: ## Run Ruff linter and formatter
	uv run ruff check . --fix
	uv run ruff format .

typecheck: ## Run mypy — zero errors required
	uv run mypy phi_scan/

test: ## Run pytest with coverage
	uv run pytest tests/ -v --cov=phi_scan

scan: ## Scan files changed since last commit
	uv run phi-scan scan --diff HEAD~1

help: ## List all available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
