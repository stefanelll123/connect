.DEFAULT_GOAL := help

PYTHON := python3
PIP := pip
RUFF := ruff
MYPY := mypy
PYTEST := pytest
DOCKER_COMPOSE := docker compose

# Directories
LIBS_DIR := libs
SERVICES_DIR := services
CONTRACTS_DIR := contracts
FRONTEND_DIR := frontend/discovery-ui

.PHONY: help install lint format type-check test test-unit test-integration \
        build up down seed reset clean install-pre-commit

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install all packages in development mode
	$(PIP) install -e "$(LIBS_DIR)/common[dev]"
	$(PIP) install -e "$(SERVICES_DIR)/discovery[dev]"
	$(PIP) install -e "$(SERVICES_DIR)/sentinel[dev]"
	@echo "✓ Python packages installed"

install-pre-commit: ## Install pre-commit hooks
	pre-commit install
	@echo "✓ Pre-commit hooks installed"

lint: ## Run ruff linter on all Python sources
	$(RUFF) check $(LIBS_DIR)/ $(SERVICES_DIR)/
	@echo "✓ Lint passed"

format: ## Auto-format all Python sources with ruff
	$(RUFF) format $(LIBS_DIR)/ $(SERVICES_DIR)/
	$(RUFF) check --fix $(LIBS_DIR)/ $(SERVICES_DIR)/
	@echo "✓ Format complete"

type-check: ## Run mypy on shared libraries (strict) and services
	$(MYPY) $(LIBS_DIR)/common/src/
	$(MYPY) --config-file $(SERVICES_DIR)/discovery/pyproject.toml $(SERVICES_DIR)/discovery/src/
	$(MYPY) --config-file $(SERVICES_DIR)/sentinel/pyproject.toml $(SERVICES_DIR)/sentinel/src/
	@echo "✓ Type check passed"

test: ## Run all tests with coverage
	$(PYTEST) $(LIBS_DIR)/ $(SERVICES_DIR)/ \
	  --cov=$(LIBS_DIR)/common/src \
	  --cov=$(SERVICES_DIR)/discovery/src \
	  --cov=$(SERVICES_DIR)/sentinel/src \
	  --cov-report=html:htmlcov \
	  --cov-report=term-missing \
	  --cov-fail-under=80

test-unit: ## Run unit tests only (no Docker required)
	$(PYTEST) $(LIBS_DIR)/ $(SERVICES_DIR)/ \
	  -m "not integration and not e2e" \
	  --cov=$(LIBS_DIR)/common/src \
	  --cov-report=term-missing

test-integration: ## Run integration tests (requires docker compose up)
	$(PYTEST) tests/integration/ -m "integration" -v

test-e2e: ## Run end-to-end tests
	$(PYTEST) tests/e2e/ -m "e2e" -v --timeout=120

build: ## Build all Docker images
	$(DOCKER_COMPOSE) build
	@echo "✓ Docker images built"

up: ## Start local development environment (uses .env.local if present)
	@if [ -f .env.local ]; then \
		$(DOCKER_COMPOSE) --env-file .env.local up -d; \
	else \
		echo "Warning: .env.local not found — copy .env.local.example to .env.local first"; \
		$(DOCKER_COMPOSE) up -d; \
	fi
	@echo "✓ Services started — run 'make seed' to populate test data"

down: ## Stop local development environment
	$(DOCKER_COMPOSE) down
	@echo "✓ Services stopped"

seed: ## Populate local development database with test data
	$(PYTHON) scripts/seed.py
	@echo "✓ Seed complete"

reset: ## Destroy and recreate local environment — clears all data (runs seed.py)
	bash scripts/reset.sh
	@echo "✓ Environment reset"

clean: ## Remove build artifacts and caches
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -name "coverage.xml" -delete 2>/dev/null || true
	find . -name ".coverage" -delete 2>/dev/null || true
	@echo "✓ Clean complete"

contracts-install: ## Install Hardhat dependencies
	cd $(CONTRACTS_DIR) && npm ci
	@echo "✓ Contract dependencies installed"

contracts-test: ## Run Hardhat tests
	cd $(CONTRACTS_DIR) && npx hardhat test
	@echo "✓ Contract tests passed"

contracts-compile: ## Compile Solidity contracts
	cd $(CONTRACTS_DIR) && npx hardhat compile
	@echo "✓ Contracts compiled"

contracts-deploy-local: ## Deploy contracts to local Anvil/Hardhat node
	powershell.exe -ExecutionPolicy Bypass -File scripts/deploy-contracts-local.ps1
	@echo "✓ Contracts deployed to localhost"

contracts-export-abis: ## Export ABI JSON files to contracts/abis/
	cd $(CONTRACTS_DIR) && npx ts-node scripts/export-abis.ts
	@echo "✓ ABIs exported to contracts/abis/"

contracts-lint-sol: ## Run Solhint on Solidity contracts
	cd $(CONTRACTS_DIR) && npx solhint 'contracts/**/*.sol'
	@echo "✓ Solhint passed"

frontend-install: ## Install frontend dependencies
	cd $(FRONTEND_DIR) && npm ci
	@echo "✓ Frontend dependencies installed"

frontend-build: ## Build frontend for production
	cd $(FRONTEND_DIR) && npm run build
	@echo "✓ Frontend built"

frontend-dev: ## Start frontend dev server
	cd $(FRONTEND_DIR) && npm run dev

frontend-lint: ## Lint frontend TypeScript/React
	cd $(FRONTEND_DIR) && npm run lint
	@echo "✓ Frontend lint passed"
