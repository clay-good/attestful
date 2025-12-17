# Attestful Makefile
# Development automation for the Attestful compliance platform

.PHONY: help install install-dev install-all test test-unit test-integration \
        lint format type-check security-check check all clean build docs \
        docker-build docker-run db-init db-migrate db-upgrade db-downgrade

# Default target
.DEFAULT_GOAL := help

# Variables
PYTHON := python
POETRY := poetry
PYTEST := $(POETRY) run pytest
MYPY := $(POETRY) run mypy
RUFF := $(POETRY) run ruff
BLACK := $(POETRY) run black
BANDIT := $(POETRY) run bandit
ALEMBIC := $(POETRY) run alembic

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

# ============================================================================
# Help
# ============================================================================

help: ## Show this help message
	@echo "$(BLUE)Attestful$(NC) - OSCAL-first compliance automation platform"
	@echo ""
	@echo "$(GREEN)Usage:$(NC)"
	@echo "  make <target>"
	@echo ""
	@echo "$(GREEN)Targets:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(BLUE)%-20s$(NC) %s\n", $$1, $$2}'

# ============================================================================
# Installation
# ============================================================================

install: ## Install core dependencies
	$(POETRY) install --no-dev

install-dev: ## Install development dependencies
	$(POETRY) install
	$(POETRY) run pre-commit install

install-all: ## Install all dependencies including optional extras
	$(POETRY) install --all-extras
	$(POETRY) run pre-commit install

# ============================================================================
# Testing
# ============================================================================

test: ## Run all tests with coverage
	$(PYTEST)

test-unit: ## Run unit tests only
	$(PYTEST) tests/unit -m unit

test-integration: ## Run integration tests only
	$(PYTEST) tests/integration -m integration

test-fast: ## Run tests without coverage (faster)
	$(PYTEST) --no-cov -x

test-verbose: ## Run tests with verbose output
	$(PYTEST) -v --tb=long

# ============================================================================
# Code Quality
# ============================================================================

lint: ## Run linter (ruff)
	$(RUFF) check src tests

lint-fix: ## Run linter and fix auto-fixable issues
	$(RUFF) check src tests --fix

format: ## Format code with black
	$(BLACK) src tests

format-check: ## Check code formatting without changes
	$(BLACK) src tests --check

type-check: ## Run type checker (mypy)
	$(MYPY) src

security-check: ## Run security scanner (bandit)
	$(BANDIT) -r src -c pyproject.toml

check: lint type-check security-check test ## Run all checks (lint, type, security, test)

all: format check ## Format and run all checks

# ============================================================================
# Build & Distribution
# ============================================================================

clean: ## Clean build artifacts
	rm -rf build dist *.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	rm -rf htmlcov .coverage coverage.xml
	rm -rf __pycache__ **/__pycache__
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

build: clean ## Build distribution packages
	$(POETRY) build

publish-test: build ## Publish to TestPyPI
	$(POETRY) publish -r testpypi

publish: build ## Publish to PyPI
	$(POETRY) publish

# ============================================================================
# Documentation
# ============================================================================

docs: ## Build documentation
	@echo "$(YELLOW)Documentation build not yet configured$(NC)"
	@echo "Consider using mkdocs or sphinx"

docs-serve: ## Serve documentation locally
	@echo "$(YELLOW)Documentation serve not yet configured$(NC)"

# ============================================================================
# Docker
# ============================================================================

docker-build: ## Build Docker image
	docker build -t attestful:latest .

docker-build-dev: ## Build Docker development image
	docker build -t attestful:dev -f docker/Dockerfile.dev .

docker-run: ## Run Docker container
	docker run -it --rm attestful:latest

docker-compose-up: ## Start all services with docker-compose
	docker-compose up -d

docker-compose-down: ## Stop all services
	docker-compose down

# ============================================================================
# Database
# ============================================================================

db-init: ## Initialize database
	$(POETRY) run attestful configure init

db-migrate: ## Generate new migration
	@read -p "Migration message: " msg; \
	$(ALEMBIC) revision --autogenerate -m "$$msg"

db-upgrade: ## Apply all pending migrations
	$(ALEMBIC) upgrade head

db-downgrade: ## Revert last migration
	$(ALEMBIC) downgrade -1

db-history: ## Show migration history
	$(ALEMBIC) history

db-current: ## Show current migration
	$(ALEMBIC) current

# ============================================================================
# Development Utilities
# ============================================================================

shell: ## Start Python shell with project context
	$(POETRY) run python

repl: ## Start IPython REPL (if installed)
	$(POETRY) run ipython

run: ## Run the CLI
	$(POETRY) run attestful

run-api: ## Run the API server (requires enterprise extras)
	$(POETRY) run attestful api --reload

run-dashboard: ## Run the dashboard (requires enterprise extras)
	$(POETRY) run attestful dashboard

# ============================================================================
# OSCAL
# ============================================================================

oscal-download: ## Download official OSCAL catalogs
	@echo "$(BLUE)Downloading NIST 800-53 Rev 5 catalog...$(NC)"
	curl -L -o data/oscal/catalogs/nist-800-53-rev5.json \
		https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json
	@echo "$(GREEN)Done!$(NC)"

oscal-validate: ## Validate OSCAL documents
	$(POETRY) run attestful oscal validate data/oscal/

# ============================================================================
# CI/CD Helpers
# ============================================================================

ci-install: ## Install dependencies for CI
	$(POETRY) install --with dev

ci-test: ## Run tests for CI (with JUnit output)
	$(PYTEST) --junitxml=test-results.xml

ci-lint: ## Run linting for CI
	$(RUFF) check src tests --output-format=github

ci: ci-install lint type-check ci-test ## Full CI pipeline

# ============================================================================
# Release
# ============================================================================

version: ## Show current version
	@$(POETRY) version

version-patch: ## Bump patch version
	$(POETRY) version patch

version-minor: ## Bump minor version
	$(POETRY) version minor

version-major: ## Bump major version
	$(POETRY) version major

changelog: ## Generate changelog (requires git-cliff or similar)
	@echo "$(YELLOW)Changelog generation not yet configured$(NC)"
